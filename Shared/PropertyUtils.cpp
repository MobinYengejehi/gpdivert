#include "PropertyUtils.h"

#include <fstream>
#include <sstream>

#include "boost/property_tree/json_parser.hpp"
#include "boost/property_tree/xml_parser.hpp"
#include "boost/log/sources/record_ostream.hpp"
#include "boost/property_tree/ptree_fwd.hpp"

void Utils::PTreeReadJson(PropertyTree& tree, std::string jsonRaw) {
    std::istringstream jsonRawStream(jsonRaw);

    boost::property_tree::read_json(jsonRawStream, tree);
}

void Utils::PTreeReadXml(PropertyTree& tree, std::string xmlRaw) {
    std::istringstream xmlRawStream(xmlRaw);

    boost::property_tree::read_xml(xmlRawStream, tree);
}

std::string Utils::PTreeToJson(PropertyTree& tree) {
    std::ostringstream jsonRawStream;

    boost::property_tree::write_json(jsonRawStream, tree);

    return jsonRawStream.str();
}

std::string Utils::PTreeToXml(PropertyTree& tree) {
    std::ostringstream xmlRawStream;

    boost::property_tree::write_xml(xmlRawStream, tree);

    return xmlRawStream.str();
}