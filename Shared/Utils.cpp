#include "Utils.h"

#include <ctime>
#include <filesystem>
#include <locale>
#include <codecvt>

#include <shellapi.h>

std::string Utils::File::Read(std::string path)
{
    path = Path::GetWindowsPathFormat(path);

    if (path.empty())
    {
        return "";
    }

    FILE* file = NULL;

    fopen_s(&file, path.c_str(), "rb");

    if (file == NULL)
    {
        return "";
    }

    fseek(file, 0, SEEK_END);
    int size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (size < 1)
    {
        fclose(file);
        return "";
    }

    char* buffer = new char[size];

    if (fread((void*)buffer, size, 1, file) < 1)
    {
        fclose(file);
        return "";
    }

    fclose(file);

    std::string bufferStr(buffer, size);

    delete buffer;

    return bufferStr;
}

size_t Utils::File::Write(std::string path, std::string data, bool createIfNotExists)
{
    path = Path::GetWindowsPathFormat(path);

    if (path.empty())
    {
        return 0;
    }

    if (data.empty())
    {
        return 0;
    }

    if (!createIfNotExists && !Exists(path))
    {
        return 0;
    }

    FILE* file = NULL;

    fopen_s(&file, path.c_str(), "wb");

    if (!file)
    {
        return 0;
    }

    size_t bytesWritten = fwrite((void*)data.data(), data.size(), 1, file);

    fclose(file);

    return bytesWritten;
}

bool Utils::File::Exists(std::string path)
{
    path = Path::GetWindowsPathFormat(path);

    if (path.empty())
    {
        return false;
    }

    FILE* file = NULL;

    fopen_s(&file, path.c_str(), "rb");

    bool result = file != NULL;

    if (result)
    {
        fclose(file);
    }
    
    return result;
}

bool Utils::File::Remove(std::string path)
{
    path = Path::GetWindowsPathFormat(path);

    if (path.empty())
    {
        return false;
    }

    return remove(path.c_str()) == 0;
}

bool Utils::File::Open(std::string path)
{
    path = Path::GetWindowsPathFormat(path);

    if (path.empty())
    {
        return false;
    }

    SHELLEXECUTEINFOW shellExecuteInfo = { 0 };

    shellExecuteInfo.lpVerb = L"runas";
    shellExecuteInfo.lpFile = ConvertStringToWString(path).c_str();
    shellExecuteInfo.lpParameters = L"";
    shellExecuteInfo.nShow = SW_NORMAL;

    return ShellExecuteExW(&shellExecuteInfo);
}

std::string Utils::Path::GetUnixPathFormat(std::string path)
{
    return ReplaceString(path, "\\", "/");
}

std::string Utils::Path::GetWindowsPathFormat(std::string path)
{
    return ReplaceString(path, "/", "\\");
}

std::string Utils::Path::Join(std::string path, const std::vector<std::string>& what, const std::string& with)
{
    return path + with + ConcatString(what, with);
}

std::string Utils::Path::GetApplicationPath()
{
    char applicationPath[MAX_PATH];
    
    if (GetModuleFileNameA(NULL, applicationPath, MAX_PATH) == 0)
    {
        return "";
    }

    return std::string(applicationPath);
}

std::string Utils::Path::GetApplicationUnixPath()
{
    return GetUnixPathFormat(GetApplicationPath());
}

std::string Utils::Path::GetApplicationDirectory()
{
    return GetPathDirectory(GetApplicationUnixPath());
}

std::string Utils::Path::GetPathFileName(std::string path, bool withoutExtention, std::string format)
{
    std::vector<std::string> chunks;

    if (SplitString(path, format, chunks) == 0)
    {
        return "";
    }

    std::string fileName = chunks[chunks.size() - 1];

    if (withoutExtention)
    {
        chunks.clear();

        if (SplitString(path, ".", chunks) == 0)
        {
            return "";
        }

        fileName = chunks[0];
    }

    return fileName;
}

std::string Utils::Path::GetPathFileExtention(std::string path, std::string format)
{
    std::string fileName = GetPathFileName(path, false, format);

    if (fileName.empty())
    {
        return "";
    }

    std::vector<std::string> chunks;

    if (SplitString(fileName, ".", chunks) == 0)
    {
        return "";
    }

    return chunks[chunks.size() - 1];
}

std::string Utils::Path::GetPathDirectory(std::string path, std::string format)
{
    if (path.empty())
    {
        return "";
    }

    std::vector<std::string> chunks;

    if (SplitString(path, format, chunks) == 0)
    {
        return "";
    }

    if (chunks.size() < 2)
    {
        return "";
    }

    chunks.erase(chunks.end() - 1);

    return ConcatString(chunks, format);
}

bool Utils::Path::IsDirectoryPath(std::string path, std::string format)
{
    std::string fileName = GetPathFileName(path, false, format);

    return fileName.find('.') == -1;
}

size_t Utils::SplitString(std::string content, std::string what, std::vector<std::string>& list)
{
    if (content.empty())
    {
        return 0;
    }

    size_t contentLength = content.length();
    size_t whatLength = what.length();
    
    size_t last = 0;

    for (size_t i = 0; i < contentLength; i++)
    {
        if (content.substr(i, whatLength) == what)
        {
            list.push_back(content.substr(last, i - last));

            last = i + whatLength;
        }
    }

    list.push_back(content.substr(last, contentLength));

    return list.size();
}

std::string Utils::ConcatString(const std::vector<std::string>& list, std::string with)
{
    std::string result = "";

    for (const std::string& chunk : list)
    {
        result += chunk + with;
    }

    if (!result.empty())
    {
        result = result.substr(0, result.length() - with.length());
    }

    return result;
}

std::string Utils::ReplaceString(std::string content, std::string what, std::string with)
{
    if (content.empty() || what.empty() || with.empty())
    {
        return content;
    }

    std::vector<std::string> chunks;

    SplitString(content, what, chunks);

    return ConcatString(chunks, with);
}

std::string Utils::ConvertWStringToString(std::wstring wstr)
{
    size_t size = wstr.size() + 1;

    char* result = (char*)malloc(size);

    sprintf_s(result, size, "%ws", wstr.c_str());

    std::string resultStr = result;
    
    free(result);

    return resultStr;
}

std::wstring Utils::ConvertStringToWString(std::string str)
{
    if (str.empty())
    {
        return std::wstring();
    }

    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

Utils::TickCount Utils::GetTickCount()
{
    return GetTickCount64();
}

std::string Utils::GetCurrentDateTimeString()
{
    std::time_t now = std::time(NULL);
    std::tm     localTime;

    localtime_s(&localTime, &now);

    char date[80];
    std::strftime(date, sizeof(date), "%Y.%m.%d %H:%M:%S", &localTime);

    return std::string(date);
}

bool Utils::IsConsoleWindowFocused()
{
    HWND consoleWindow = GetConsoleWindow();
    HWND focusedWindow = GetForegroundWindow();

    return consoleWindow == focusedWindow;
}

std::string Utils::WaitToPressEnter(std::string text)
{
    std::string input;

    L_INFO << text << L_END;

    std::cin >> input;

    return input;
}