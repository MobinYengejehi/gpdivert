#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <string>
#include <vector>
#include <Windows.h>
#include <iostream>

#define LOGGER                 std::cout << "[" << Utils::GetCurrentDateTimeString() << "] "
#define LOGGER_END             std::endl
#define LOGGER_CLEAR_ALL       system("cls")
#define LOGGER_FLUSH           std::flush
#define LOGGER_CLEAR_LAST_LINE std::cout << "\r" << std::string(80, ' ') << "\r" << LOGGER_FLUSH

#define L_INFO  LOGGER << "INFO: "
#define L_WARN  LOGGER << "WARNING: "
#define L_ERROR LOGGER << "ERROR: "
#define L_END   LOGGER_END

#define X_C_TO_STRING(c) #c
#define C_TO_STRING(c) X_C_TO_STRING(c)

namespace Utils
{
    using TickCount = ULONGLONG;

    namespace File {
        std::string Read(std::string path);
        size_t      Write(std::string path, std::string data, bool createIfNotExists = true);

        bool Exists(std::string path);

        bool Remove(std::string path);

        bool Open(std::string path);
    };

    namespace Path
    {
        std::string GetUnixPathFormat(std::string path);
        std::string GetWindowsPathFormat(std::string path);

        std::string Join(std::string path, const std::vector<std::string>& what, const std::string& with = "/");

        std::string GetApplicationPath();
        std::string GetApplicationUnixPath();
        std::string GetApplicationDirectory();

        std::string GetPathFileName(std::string path, bool withoutExtension = true, std::string format = "/");
        std::string GetPathFileExtention(std::string path, std::string format = "/");
        std::string GetPathDirectory(std::string path, std::string format = "/");
        bool        IsDirectoryPath(std::string path, std::string format = "/");
    };

    size_t      SplitString(std::string content, std::string what, std::vector<std::string>& list);
    std::string ConcatString(const std::vector<std::string>& list, std::string with = " ");
    std::string ReplaceString(std::string content, std::string what, std::string with);

    std::string  ConvertWStringToString(std::wstring wstr);
    std::wstring ConvertStringToWString(std::string str);

    TickCount GetTickCount();

    std::string GetCurrentDateTimeString();

    bool IsConsoleWindowFocused();

    std::string WaitToPressEnter(std::string text = "Press `Enter` to quit...");
};