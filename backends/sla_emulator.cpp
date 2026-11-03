//--------------------------------------------------------------------------------------
// File: sla_emulator.cpp
//
// libsla emulator
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------
#include "sla_emulator.h"

#include <set>
#include <sstream>
#include <stdexcept>

#include "sleigh.hh"
#include "emulate.hh"
#include "memstate.hh"

using namespace ghidra;

namespace
{

// libsla's MemoryBank::setValue()/getValue() only handle accesses that straddle two
// aligned words correctly when the bank word size equals sizeof(uintb) (8 bytes).
// Smaller word sizes corrupt multi-byte little endian writes (Ghidra issue #6404), and
// non power of two sizes (e.g. a 24-bit address space) break alignment entirely, so
// always use 8 regardless of the address size of the processor.
const int4 BANK_WORD_SIZE = sizeof(uintb);
const int4 BANK_PAGE_SIZE = 4096;
const int4 BANK_HASH_SIZE = 4096;

[[maybe_unused]] std::string xml_escape(const std::string &in)
{
    std::string out;
    for (char c : in)
    {
        switch (c)
        {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            default: out += c; break;
        }
    }
    return out;
}

// Feeds the test's initial memory to the translator (instruction decoding) and to the
// MemoryImage underlying RAM. Addresses wrap at the end of the address space.
class TestLoadImage : public LoadImage
{
    const std::map<uint64_t, uint8_t> *memory = nullptr;

public:
    TestLoadImage(void) : LoadImage("nofile") {}

    void set_memory(const std::map<uint64_t, uint8_t> *mem) { memory = mem; }

    void loadFill(uint1 *ptr, int4 size, const Address &addr) override
    {
        AddrSpace *space = addr.getSpace();
        uintb start = addr.getOffset();

        for (int4 i = 0; i < size; i++)
        {
            uintb offset = space->wrapOffset(start + i);
            ptr[i] = 0; // unspecified memory is zero
            if (memory != nullptr)
            {
                auto it = memory->find(offset);
                if (it != memory->end())
                {
                    ptr[i] = it->second;
                }
            }
        }
    }

    std::string getArchType(void) const override { return "verifier"; }
    void adjustVma(long adjust) override {}
};

// RAM overlay that wraps addresses at the end of the space and records every byte
// written, so that writes to memory not listed in the expected state can be detected.
class TrackingPageOverlay : public MemoryPageOverlay
{
    std::set<uintb> written;

    uintb wrap(uintb addr) const { return getSpace()->wrapOffset(addr); }

protected:
    void insert(uintb addr, uintb val) override
    {
        addr = wrap(addr);
        for (int4 i = 0; i < getWordSize(); i++)
        {
            written.insert(addr + i);
        }
        MemoryPageOverlay::insert(addr, val);
    }

    uintb find(uintb addr) const override
    {
        return MemoryPageOverlay::find(wrap(addr));
    }

    void setPage(uintb addr, const uint1 *val, int4 skip, int4 size) override
    {
        addr = wrap(addr);
        for (int4 i = 0; i < size; i++)
        {
            written.insert(addr + skip + i);
        }
        MemoryPageOverlay::setPage(addr, val, skip, size);
    }

    void getPage(uintb addr, uint1 *res, int4 skip, int4 size) const override
    {
        MemoryPageOverlay::getPage(wrap(addr), res, skip, size);
    }

public:
    TrackingPageOverlay(AddrSpace *spc, int4 ws, int4 ps, MemoryBank *ul)
        : MemoryPageOverlay(spc, ws, ps, ul) {}

    const std::set<uintb> &written_bytes(void) const { return written; }
};

// Thrown (internally) when the instruction under test completed but the emulator could
// not decode the instruction at the next address.
struct NextInstructionDecodeFailure {};

// EmulatePcodeCache eagerly decodes the instruction at the fallthrough/branch target as
// soon as the current instruction finishes. Unit tests usually have garbage (or nothing)
// at that address, so a decode failure there is not an error in the instruction being
// tested. The next address is already recorded when decoding fails, so stop there.
class SingleStepEmulator : public EmulatePcodeCache
{
    bool stepping = false;

    template <typename F>
    void transition(F &&f)
    {
        if (!stepping)
        {
            f();
            return;
        }
        try
        {
            f();
        }
        catch (const LowlevelError &)
        {
            throw NextInstructionDecodeFailure();
        }
    }

protected:
    // Only throws if decoding the next instruction fails
    void fallthruOp(void) override
    {
        transition([this]() { EmulatePcodeCache::fallthruOp(); });
    }

public:
    SingleStepEmulator(Translate *t, MemoryState *s, BreakTable *b) : EmulatePcodeCache(t, s, b) {}

    // Used for the initial address and every non-relative branch. current_address is
    // updated before decoding, so a decode failure still leaves the branch target.
    void setExecuteAddress(const Address &addr) override
    {
        transition([this, &addr]() { EmulatePcodeCache::setExecuteAddress(addr); });
    }

    // Execute exactly one instruction starting at addr. Exceptions from the instruction
    // itself (including failing to decode it) propagate to the caller.
    void step(const Address &addr)
    {
        stepping = false;
        setExecuteAddress(addr);
        setHalt(false);

        stepping = true;
        try
        {
            executeInstruction();
        }
        catch (const NextInstructionDecodeFailure &)
        {
            // instruction under test completed
        }
        stepping = false;
    }
};

}

struct SlaEmulator::Impl
{
    const TEST_PARAMS &params;
    DocumentStorage store;
    TestLoadImage loader;
    std::unique_ptr<ContextInternal> context;
    Sleigh trans;

    explicit Impl(const TEST_PARAMS &p)
        : params(p), context(new ContextInternal()), trans(&loader, context.get())
    {
        try
        {
#if __has_include("slaformat.hh")
            // Ghidra >= 11.1: .sla files are a compressed binary format. The <sleigh> tag
            // holds the path and Sleigh::initialize() opens the file itself.
            std::istringstream sleigh_tag("<sleigh>" + xml_escape(params.sla_filename) + "</sleigh>");
            store.registerTag(store.parseDocument(sleigh_tag)->getRoot());
#else
            // Older Ghidra: .sla files are XML
            store.registerTag(store.openDocument(params.sla_filename)->getRoot());
#endif
            trans.initialize(store);
            apply_context();

            trans.getRegister(params.program_counter); // throws if it doesn't exist
        }
        catch (const LowlevelError &e)
        {
            throw std::runtime_error(e.explain);
        }
        catch (const DecoderError &e)
        {
            throw std::runtime_error(e.explain);
        }
    }

    void apply_context(void)
    {
        for (const auto &[name, value] : params.context)
        {
            trans.setContextDefault(name, value);
        }
    }

    // Instruction decode and p-code caches are keyed by address, so they must be
    // flushed before every test. Re-initializing an already loaded Sleigh object
    // only re-registers context variables; the .sla is not parsed again.
    void reset(void)
    {
        std::unique_ptr<ContextInternal> new_context(new ContextInternal());
        trans.reset(&loader, new_context.get());
        trans.initialize(store);
        context = std::move(new_context);
        apply_context();
    }

    void run(const TEST_CASE &test, EMU_RESULT &result)
    {
        result = EMU_RESULT();

        loader.set_memory(&test.initial.memory);
        reset();

        AddrSpace *ram = trans.getDefaultCodeSpace();
        MemoryImage loadmemory(ram, BANK_WORD_SIZE, BANK_PAGE_SIZE, &loader);
        TrackingPageOverlay ramstate(ram, BANK_WORD_SIZE, BANK_PAGE_SIZE, &loadmemory);
        MemoryHashOverlay registerstate(trans.getSpaceByName("register"), BANK_WORD_SIZE, BANK_PAGE_SIZE, BANK_HASH_SIZE, nullptr);
        MemoryHashOverlay tmpstate(trans.getUniqueSpace(), BANK_WORD_SIZE, BANK_PAGE_SIZE, BANK_HASH_SIZE, nullptr);

        MemoryState memstate(&trans);
        memstate.setMemoryBank(&ramstate);
        memstate.setMemoryBank(&registerstate);
        memstate.setMemoryBank(&tmpstate);

        // any other processor spaces (e.g. separate io/data spaces) start zeroed
        std::vector<std::unique_ptr<MemoryPageOverlay>> other_banks;
        for (int4 i = 0; i < trans.numSpaces(); i++)
        {
            AddrSpace *spc = trans.getSpace(i);
            if (spc == nullptr || spc->getType() != IPTR_PROCESSOR || memstate.getMemoryBank(spc) != nullptr)
            {
                continue;
            }
            other_banks.emplace_back(new MemoryPageOverlay(spc, BANK_WORD_SIZE, BANK_PAGE_SIZE, nullptr));
            memstate.setMemoryBank(other_banks.back().get());
        }

        // set initial registers. Register names were validated before the run started.
        for (const auto &[register_name, value] : test.initial.registers)
        {
            const VarnodeData &vn = trans.getRegister(register_name);
            memstate.setValue(vn.space, vn.offset, vn.size, value);
        }

        BreakTableCallBack breaktable(&trans);
        SingleStepEmulator emulator(&trans, &memstate, &breaktable);

        try
        {
            uintb pc = memstate.getValue(params.program_counter);
            emulator.step(Address(ram, ram->wrapOffset(pc)));
            memstate.setValue(params.program_counter, emulator.getExecuteAddress().getOffset());
        }
        catch (const LowlevelError &e)
        {
            result.error = e.explain;
        }
        catch (const std::exception &e)
        {
            result.error = e.what();
        }
        catch (...)
        {
            result.error = "unknown exception";
        }

        // record final register state
        auto record_register = [&](const std::string &name)
        {
            result.state.registers[name] = memstate.getValue(name);
        };
        for (const auto &[register_name, value] : test.final.registers)
        {
            record_register(register_name);
        }
        for (const auto &[register_name, value] : test.initial.registers)
        {
            if (result.state.registers.count(register_name) == 0)
            {
                record_register(register_name);
            }
        }

        // record final memory state
        for (const auto &[address, value] : test.final.memory)
        {
            result.state.memory[address] = memstate.getValue(ram, ram->wrapOffset(address), 1);
        }

        if (params.check_unlisted_writes)
        {
            for (uintb address : ramstate.written_bytes())
            {
                if (test.final.memory.count(address) != 0)
                {
                    continue;
                }

                auto it = test.initial.memory.find(address);
                uint8_t before = (it == test.initial.memory.end()) ? 0 : it->second;
                uint8_t after = memstate.getValue(ram, address, 1);
                if (before != after)
                {
                    result.unlisted_writes[address] = after;
                }
            }
        }
    }
};

void SlaEmulator::global_init(void)
{
    AttributeId::initialize();
    ElementId::initialize();
}

SlaEmulator::SlaEmulator(const TEST_PARAMS &test_params) : impl(new Impl(test_params)) {}

SlaEmulator::~SlaEmulator() = default;

SLA_INFO SlaEmulator::info(void) const
{
    AddrSpace *ram = impl->trans.getDefaultCodeSpace();
    SLA_INFO info;
    info.ram_space = ram->getName();
    info.addr_size = ram->getAddrSize();
    info.word_size = ram->getWordSize();
    info.big_endian = ram->isBigEndian();
    return info;
}

bool SlaEmulator::has_register(const std::string &name) const
{
    try
    {
        impl->trans.getRegister(name);
        return true;
    }
    catch (const LowlevelError &)
    {
        return false;
    }
}

std::vector<std::string> SlaEmulator::register_names(void) const
{
    std::map<VarnodeData, std::string> reglist;
    impl->trans.getAllRegisters(reglist);

    std::set<std::string> names;
    for (const auto &[vn, name] : reglist)
    {
        names.insert(name);
    }
    return std::vector<std::string>(names.begin(), names.end());
}

void SlaEmulator::run(const TEST_CASE &test, EMU_RESULT &result)
{
    try
    {
        impl->run(test, result);
    }
    catch (const LowlevelError &e)
    {
        result.error = "setup failed: " + e.explain;
    }
}
