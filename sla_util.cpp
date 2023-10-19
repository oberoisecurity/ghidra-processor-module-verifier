//--------------------------------------------------------------------------------------
// File: sla_util.cpp
//
// Misc helper functions for working with .sla files
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/foreach.hpp>
#include <string>
#include <iostream>
#include <fstream>

#define SLEIGH_VERSION 3

using namespace std;
namespace pt = boost::property_tree;

int sla_get_word_size(string sla_filename, unsigned int& word_size)
{
    string default_space;
    string space_name;
    int sleigh_version = 0;
    int size = 0;;

    // Create empty property tree object
    pt::ptree tree;

    // Parse the XML into the property tree.
    try
    {
        pt::read_xml(sla_filename, tree);
    } catch(...)
    {
        cout << "[-] Exception when opening .sla!" << endl;
        return -1;
    }

    sleigh_version = tree.get("sleigh.<xmlattr>.version", 0);
    if(sleigh_version != SLEIGH_VERSION)
    {
        cout << "[-] Invalid sleigh version (" << sleigh_version << ")!" << endl;
        cout << "[-] Is the .sla file correct?" << endl;
        return -1;
    }

    default_space = tree.get("sleigh.spaces.<xmlattr>.defaultspace", "");
    if(default_space == "")
    {
        cout << "[-] Failed to parse sleigh default space!" << endl;
        return -1;
    }

    BOOST_FOREACH(pt::ptree::value_type &v, tree.get_child("sleigh.spaces"))
    {
        if(v.first != "space")
        {
            continue;
        }
        else
        {
            space_name = v.second.get("<xmlattr>.name", "");

            if(space_name != default_space)
            {
                continue;
            }

            // fopund the default space
            size = v.second.get("<xmlattr>.size", 0);
            if(size == 0)
            {
                continue;
            }
            else
            {
                // got the word size
                word_size = size;
                return 0;
            }
        }
    }

    return -1;
}
