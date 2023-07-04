#include <exception>

#include "CrashCatcher.h"

void test_throw()
{
	throw 100;
}

void test_SIGHUP()    {raise(SIGHUP);}
void test_SIGINT()    {raise(SIGINT);}
void test_SIGQUIT()   {raise(SIGQUIT);}
void test_SIGILL()    {raise(SIGILL);}
void test_SIGTRAP()   {raise(SIGTRAP);}
void test_SIGABRT()   {raise(SIGABRT);}
void test_SIGBUS()    {raise(SIGBUS);}
void test_SIGFPE()    {raise(SIGFPE);}
void test_SIGSEGV()   {raise(SIGSEGV);}
void test_SIGPIPE()   {raise(SIGPIPE);}
void test_SIGALRM()   {raise(SIGALRM);}
void test_SIGTERM()   {raise(SIGTERM);}
void test_SIGSTKFLT() {raise(SIGSTKFLT);}
void test_SIGXCPU()   {raise(SIGXCPU);}
void test_SIGXFSZ()   {raise(SIGXFSZ);}
void test_SIGVTALRM() {raise(SIGVTALRM);}
void test_SIGPROF()   {raise(SIGPROF);}
void test_SIGIO()     {raise(SIGIO);}
void test_SIGPWR()    {raise(SIGPWR);}
void test_SIGSYS()    {raise(SIGSYS);}

int main()
{
	CrashCatcher::Register();
	
	//test_throw();
	test_SIGHUP();
	//test_SIGINT();
	//test_SIGQUIT();
	//test_SIGILL();
	//test_SIGTRAP();
	//test_SIGABRT();
	//test_SIGBUS();
	//test_SIGFPE();
	//test_SIGSEGV();
	//test_SIGPIPE();
	//test_SIGALRM();
	//test_SIGTERM();
	//test_SIGSTKFLT();
	//test_SIGXCPU();
	//test_SIGXFSZ();
	//test_SIGVTALRM();
	//test_SIGPROF();
	//test_SIGIO();
	//test_SIGPWR();
	test_SIGSYS();
	
	
	return 0;
}
