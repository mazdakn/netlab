#ifndef __DB_H__
#define __DB_H__

#include <sstream>

#include <mysql++/mysql++.h>
#include <mysql++/connection.h>
#include <mysql/mysql.h>

using namespace std;

class DataBase {
                mysqlpp::Connection conn; // connection to database
        public:
		void connect(string, string, string, string); // connect to db
                void init(string); // init domain data in db
                void update(string, int, int, double, double, unsigned long long, unsigned long long); // updata domain data
		int exist(string); // check if domain data exists in db
                DataBase();
                ~DataBase();
};

#endif
