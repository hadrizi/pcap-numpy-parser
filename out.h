#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <string>


class Timer
{
private:
	// Псевдонимы типов используются для удобного доступа к вложенным типам
	using clock_t = std::chrono::high_resolution_clock;
	using second_t = std::chrono::duration<double, std::ratio<1> >;
 
	std::chrono::time_point<clock_t> m_beg;
 
public:
	Timer() : m_beg(clock_t::now())
	{
	}
 
	void reset()
	{
		m_beg = clock_t::now();
	}
 
	double elapsed() const
	{
		return std::chrono::duration_cast<second_t>(clock_t::now() - m_beg).count();
	}
};

//------------------ Binary model funcs ------------


const static void print_binary_header(const long long int& processed, const Timer& timer){
    const char separator    = ' | ';
    const int nameWidth     = 6;
    const int numWidth      = 8;

    std::cout << std::left << std::setw(nameWidth) << std::setfill(separator) << "Processed: ";
    std::cout << std::left << std::setw(numWidth) << std::setfill(separator) << processed;
    std::cout << std::endl;

    std::cout << std::left << std::setw(nameWidth) << std::setfill(separator) << "Time: ";
    std::cout << std::left << std::setw(numWidth) << std::setfill(separator) << timer.elapsed();
    std::cout << std::endl;

    float perfomance = processed / timer.elapsed();
    std::cout << std::left << std::setw(nameWidth) << std::setfill(separator) << "Perfomance: ";
    std::cout << std::left << std::setw(numWidth) << std::setfill(separator) << perfomance;
    std::cout << std::left << std::setw(numWidth) << std::setfill(separator) << " pkg/";
    std::cout << std::endl;
}

const static inline void print_binary_descion(bool result){
    result ? spdlog::info("Clean") : spdlog::critical("Atack");
}

//------------------ Complex model funcs ------------

void print_complex_header(const Timer& timer, const int& stack_count, const long long int& processed){
    const char separator    = ' ';
    const char horizontal    = '_';
    const int nameWidth     = 6;
    const int numWidth      = 8;
    const int columns       = 3;

    auto time = timer.elapsed();
    const int connection_perfomance = processed / time * 60;
    const std::string stuff(stack_count%50, '.');

    std::cout << std::left << "TO PROCESS: " << std::setw(nameWidth) << std::setfill(separator) << stack_count << std::endl;
    std::cout << std::left << "PROCESSED: " <<  std::setw(nameWidth) << std::setfill(separator) << processed << std::endl;
    std::cout << std::left << "PERFOMANCE: " << std::setw(nameWidth) << std::setfill(separator) << connection_perfomance << std::endl;
    std::cout << std::left << stuff;
    std::cout << std::endl;
}


/**
 * Print small log info for presentation on screen
 */
const void inline print_complex_connection_decision(const std::string& conn_hash, const std::string& atack_category, const double& percent){

    if (percent>=90){
        spdlog::critical("{} - {} - {}", conn_hash, atack_category, percent);
    }
    else if (percent>20 and percent<90){
        spdlog::warn("{} - {} - {}", conn_hash, atack_category, percent);
    }
    else {
        spdlog::info("{} - {} - {}", conn_hash, atack_category, percent);
    }

}

/**
 * File logger for complex model decision
 * 
 * Save full analyst info to file  
 */
void basic_logfile_example()
{
    try 
    {
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);

        std::ostringstream oss;
        oss << std::put_time(&tm, "%d-%m-%Y %H-%M-%S");
        std::string str = oss.str();

        auto logger = spdlog::basic_logger_mt("basic_logger", "logs/connections-"+str+".txt");
    }
    catch (const spdlog::spdlog_ex &ex)
    {
        std::cout << "Log init failed: " << ex.what() << std::endl;
    }
}

// //---------------- Run funciton ---------------------
// int main() 
// {
//     spdlog::info("Welcome to spdlog!");
// 	Timer timer;

//     int i=1;
    
//     while (int(timer.elapsed())<10 )
//     {
//         // print_binary_header(i, timer);
//         print_complex_header(timer, i*2, i);

//         while (i%50!=0)
//         {
//             print_complex_connection_decision("___hash___", "___category___", i);
//             // print_binary_descion(i%5);
//             i++;
//         }
//         std::system("clear");
//         i++;
//     }

// }
