#pragma once

#include <string>

#include "boost/property_tree/ptree.hpp"

namespace Utils
{
	using PropertyTree = boost::property_tree::ptree;

    template<typename KeyType = std::string>
    bool PTreeExistsItem(const PropertyTree& tree, KeyType key) {
        return tree.find(key) != tree.not_found();
    }

    template<typename ItemType, typename KeyType = std::string>
    ItemType PTreeGetItem(const PropertyTree& tree, KeyType key, ItemType defaultValue) {
        return tree.get_optional<ItemType>(key).value_or(defaultValue);
    }

    template<typename KeyType = std::string, typename ItemType = std::string>
    void PTreeSetItem(PropertyTree& tree, KeyType key, ItemType item) {
        tree.put(key, item);
    }

    void PTreeReadJson(PropertyTree& tree, std::string jsonRaw);
    void PTreeReadXml(PropertyTree& tree, std::string xmlRaw);

    std::string PTreeToJson(PropertyTree& tree);
    std::string PTreeToXml(PropertyTree& tree);
};