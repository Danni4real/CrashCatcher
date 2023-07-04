#ifndef CRASH_CATCHER_H
#define CRASH_CATCHER_H

#include <elf.h>
#include <link.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <execinfo.h>
#include <ucontext.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <regex>
#include <chrono>
#include <string>
#include <sstream>
#include <iostream>
#include <exception>

#define WorkspacePath "/tmp/" // make sure 1.it already exists; 2.program have permission(rwx) to it;

// these are signals, which will cause programe to terminate
// remove signal from this set if you have new signal handler for it
int SIG_SET[] = {SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS,
                 SIGFPE, SIGSEGV, SIGPIPE, SIGALRM, SIGTERM, SIGSTKFLT, SIGXCPU, SIGXFSZ,
                 SIGVTALRM, SIGPROF, SIGIO, SIGPWR, SIGSYS};

namespace CrashCatcher
{
using namespace std;

size_t get_file_size(const char *path)
{
    struct stat s;

    if (stat(path, &s) == -1)
    {
        fprintf(stderr, "Failed to stat file %s: %s\n", path, strerror(errno));
        return -1;
    }

    return s.st_size;
}
// TODO: 1.validate ELF file; 2.figure out actual header size of ELF (malloc);
size_t get_elf_size(const char *path)
{
    int fd;
    void *ELFheaderdata;
    Elf64_Ehdr *ELFheader;
    size_t elfsize;

    ELFheaderdata = malloc(64);

    fd = open(path, O_RDONLY);
    if(fd == -1)
    {
        fprintf(stderr, "Failed to open input file %s: %s\n",
                path,
                strerror(errno));

        return -1;
    }

    read(fd, ELFheaderdata, 64);
    ELFheader = (Elf64_Ehdr *)ELFheaderdata;

    elfsize = ELFheader->e_shoff + (ELFheader->e_shnum * ELFheader->e_shentsize);

    close(fd);
    free(ELFheaderdata);

    return elfsize;
}
// converts a address in memory to its VMA address in the executable file
size_t mem2vma(size_t mem_addr)
{
    Dl_info   dl_info;
    link_map* link_map;

    dladdr1((void*)mem_addr, &dl_info, (void**)&link_map, RTLD_DL_LINKMAP);

    return mem_addr - link_map->l_addr;
}

string run_cmd(const string& cmd)
{
    string run_result = "";

    FILE* pipe = popen(cmd.c_str(), "r");
    if(!pipe)
    {
        cerr << "run_cmd() failed: " << cmd << endl;
        return run_result;
    }

    char buf[1024] = {0};
    while(fgets(buf, sizeof(buf), pipe) != NULL)
        run_result += buf;

    pclose(pipe);

    return run_result;
}

void untar(const string& src, const string& des)
{
    char cmd[1024] = {0};

    snprintf(cmd, sizeof(cmd), "tar -xvf %s -C %s" ,src.c_str(),des.c_str());

    run_cmd(cmd);
}

void mkdir(const string& path)
{
    char cmd[1024] = {0};

    snprintf(cmd, sizeof(cmd), "mkdir %s", path.c_str());

    run_cmd(cmd);
}

void rm(const string& path)
{
    char cmd[1024] = {0};

    snprintf(cmd, sizeof(cmd), "rm -rf %s", path.c_str());

    run_cmd(cmd);
}
// extract compressed project folder from elf file
void extract_appendix(const char* elf_path, const char* tar_path)
{
    size_t elf_size    = get_elf_size(elf_path);
    size_t file_size   = get_file_size(elf_path);
    size_t append_size = file_size - elf_size;

    if(append_size > 0)
    {
        FILE *fp_elf = fopen(elf_path, "rb");
        FILE *fp_tar = fopen(tar_path, "w");

        if(fp_elf == NULL) { printf("Unable to open %s for reading: %s", elf_path, strerror(errno)); goto end; }
        if(fp_tar == NULL) { printf("Unable to open %s for writing: %s", tar_path, strerror(errno)); goto end; }

        fseek(fp_elf, elf_size, SEEK_SET);

        char ch;
        while(fread(&ch, 1, 1, fp_elf))
             fwrite(&ch, 1, 1, fp_tar);

end:
        if(fp_elf != NULL) {fclose(fp_elf);}
        if(fp_tar != NULL) {fclose(fp_tar);}
    }
}
// return CrashCatcher.h relative path
string get_relative_header_path(const char* local_proj_path)
{
    string path = __FILE__;
    string header_name = path.substr(path.find_last_of('/')+1);

    char cmd[1024] = {0};
    snprintf(cmd, sizeof(cmd), "cd %s;find . -name %s", local_proj_path, header_name.c_str());

    string result = run_cmd(cmd);

    result = result.substr(2,result.size()-3); // strip "./" and newline char

    return result;
}
// return project path at compiling machine
string get_remote_proj_path(const string& relative_header_path)
{
    string str    = __FILE__;
    string subStr = relative_header_path;

    size_t pos = str.find(subStr);

    if(pos != string::npos)
        str.erase(pos,subStr.length());

    return str;
}
// generate project path at executing machine
string gen_local_proj_path()
{
    using namespace std::chrono;

    string path = WorkspacePath;

    uint64_t now = duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count();

    path += to_string(now);

    mkdir(path);

    return path;
}

void print_backtrace(int)
{
    void *callstack[1024];
    int frame_count = backtrace(callstack, sizeof(callstack)/sizeof(callstack[0]));

    Dl_info dl_info;
    if(dladdr(callstack[0],&dl_info) == 0)
        exit(0);

    const char* bin_path = dl_info.dli_fname;
    cout << bin_path << " crashed!!!";

    string local_proj_path = gen_local_proj_path();
    string tar_path = local_proj_path + "/code.tar.gz";

    extract_appendix(bin_path, tar_path.c_str());
    untar(tar_path, local_proj_path);

    string remote_proj_path = get_remote_proj_path(get_relative_header_path(local_proj_path.c_str()));

    cout << "\n\nBacktrace raw:\n";
    char** backtrace = backtrace_symbols(callstack, frame_count);
    for (size_t i = 0; i < frame_count; i++)
    {
        cout << backtrace[i] << endl;
    }

    cout << "\n\nBacktrace detail:";
    for(int i = 2; i < frame_count; i++)
    {
        char cmd[1024] = {0};
        size_t vma_addr = mem2vma((size_t)callstack[i]) - 1;

        snprintf(cmd,
                 sizeof(cmd),
                 "cd %s;"
                 "addr2line -e %s -Ci %zx 2>&1 | while read line;"
                                                "do s_l=${line#%s};"
                                                    "s=${s_l%:*};"
                                                    "l=${s_l#*:};"
                                                    "echo $s_l;"
                                                    "head -n $l $s | tail -1;echo '';"
                                                "done",
                 local_proj_path.c_str(), bin_path, vma_addr, remote_proj_path.c_str());

        cout << endl << run_cmd(cmd);

        Dl_info dl_info;
        dladdr(callstack[i],&dl_info);
        if(dl_info.dli_sname != NULL)
        {
            cout << " at " << dl_info.dli_sname << endl;
        }
    }

    rm(local_proj_path);

    exit(0);
}

void handle_exception()
{
    print_backtrace(0);
}

void Register()
{
    struct sigaction sigact;

    sigact.sa_handler = print_backtrace;
    sigact.sa_flags   = SA_RESTART | SA_SIGINFO;

    for(int sig : SIG_SET)
    {
        if(sigaction(sig, &sigact, (struct sigaction *)NULL) != 0)
        {
            fprintf(stderr, "error setting signal handler for %d (%s)\n", sig, strsignal(sig));
            exit(EXIT_FAILURE);
        }
    }

    std::set_terminate(handle_exception);
}
}

#endif

