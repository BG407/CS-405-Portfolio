// SQLInjection.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <algorithm>
#include <iostream>
#include <locale>
#include <tuple>
#include <vector>
#include "sqlite3.h"

// DO NOT CHANGE
typedef std::tuple<std::string, std::string, std::string> user_record;
const std::string str_where = " where ";

// DO NOT CHANGE
static int callback(void* NotUsed, int argc, char** argv, char** azColName)
{
    std::vector< user_record >* records =
        static_cast<std::vector< user_record > *>(NotUsed);

    if (argc == 3)
    {
        records->push_back(std::make_tuple(argv[0], argv[1], argv[2]));
    }
    return 0;
}

// DO NOT CHANGE
bool initialize_database(sqlite3* db)
{
    char* error_message = NULL;

    // drop table if it already exists
    std::string sql =
        "DROP TABLE IF EXISTS USERS;";
    if (sqlite3_exec(db, sql.c_str(), callback, NULL, &error_message) != SQLITE_OK)
    {
        std::cout << "Failed to drop old USERS table. ERROR=" << error_message << std::endl;
        sqlite3_free(error_message);
        return false;
    }

    // create new user table
    sql =
        "CREATE TABLE USERS("  \
        "ID INT PRIMARY KEY     NOT NULL," \
        "NAME           TEXT    NOT NULL," \
        "PASSWORD       TEXT    NOT NULL);";

    if (sqlite3_exec(db, sql.c_str(), callback, NULL, &error_message) != SQLITE_OK)
    {
        std::cout << "Failed to create new USERS table. ERROR=" << error_message << std::endl;
        sqlite3_free(error_message);
        return false;
    }

    // populate with some test data
    sql =
        "INSERT INTO USERS (ID, NAME, PASSWORD)"
        "VALUES (1, 'Fred', 'Flintstone');"
        "INSERT INTO USERS (ID, NAME, PASSWORD)"
        "VALUES (2, 'Barney', 'Rubble');"
        "INSERT INTO USERS (ID, NAME, PASSWORD)"
        "VALUES (3, 'Wilma', 'Flinstone');"
        "INSERT INTO USERS (ID, NAME, PASSWORD)"
        "VALUES (4, 'Betty', 'Rubble');";

    int result = sqlite3_exec(db, sql.c_str(), callback, NULL, &error_message);
    if (result != SQLITE_OK)
    {
        std::cout << "Data failed to insert to USERS table. ERROR = " << error_message << std::endl;
        sqlite3_free(error_message);
        return false;
    }

    return true;
}

bool run_query(sqlite3* db, const std::string& sql, std::vector< user_record >& records)
{
    // TODO: Fix this method to fail and display an error if there is a suspected SQL Injection
    //  NOTE: You cannot just flag 1=1 as an error, since 2=2 will work just as well. You need
    //  something more generic

    // detect OR literal=literal injection
    {
        std::string lower_sql = sql;
        std::transform(lower_sql.begin(), lower_sql.end(), lower_sql.begin(), ::tolower);
        auto trim = [](const std::string& s) {
            size_t a = s.find_first_not_of(" \t");
            size_t b = s.find_last_not_of(" \t");
            if (a == std::string::npos) return std::string();
            return s.substr(a, b - a + 1);
            };
        auto strip_quotes = [](const std::string& s) {
            if (s.size() >= 2 && ((s.front() == '\'' && s.back() == '\'') || (s.front() == '\"' && s.back() == '\"')))
                return s.substr(1, s.size() - 2);
            return s;
            };
        size_t pos = lower_sql.find(" or ");
        if (pos != std::string::npos) {
            size_t eq_pos = lower_sql.find('=', pos + 4);
            if (eq_pos != std::string::npos) {
                std::string op1 = trim(sql.substr(pos + 4, eq_pos - (pos + 4)));
                size_t start2 = eq_pos + 1;
                size_t end2 = lower_sql.find_first_of(" ;", start2);
                if (end2 == std::string::npos) end2 = sql.size();
                std::string op2 = trim(sql.substr(start2, end2 - start2));
                if (strip_quotes(op1) == strip_quotes(op2)) {
                    std::cout << "Potential SQL injection detected and blocked for query: " << sql << std::endl;
                    return false;
                }
            }
        }
    }

    // clear any prior results
    records.clear();

    char* error_message;
    if (sqlite3_exec(db, sql.c_str(), callback, &records, &error_message) != SQLITE_OK)
    {
        std::cout << "Data failed to be queried from USERS table. ERROR = " << error_message << std::endl;
        sqlite3_free(error_message);
        return false;
    }

    std::cout << std::endl << "SQL: " << sql << " ==> " << records.size() << " records found." << std::endl;
    for (auto record : records)
    {
        std::cout << "User: " << std::get<1>(record)
            << " [UID=" << std::get<0>(record)
            << " PWD=" << std::get<2>(record) << "]" << std::endl;
    }

    return true;
}

// DO NOT CHANGE
void dump_results(const std::string& sql, const std::vector< user_record >& records)
{
    std::cout << std::endl << "SQL: " << sql << " ==> " << records.size() << " records found." << std::endl;
    for (auto record : records)
    {
        std::cout << "User: " << std::get<1>(record)
            << " [UID=" << std::get<0>(record)
            << " PWD=" << std::get<2>(record) << "]" << std::endl;
    }
}

// DO NOT CHANGE
void run_queries(sqlite3* db)
{
    char* error_message = NULL;
    std::vector< user_record > records;

    // query all
    std::string sql = "SELECT * from USERS";
    if (!run_query(db, sql, records)) return;
    dump_results(sql, records);

    //  query 1
    sql = "SELECT ID, NAME, PASSWORD FROM USERS WHERE NAME='Fred'";
    if (!run_query(db, sql, records)) return;
    dump_results(sql, records);

    //  run query 1 with injection 5 times
    for (int i = 0; i < 5; ++i)
    {
        std::string injectedSQL = sql + " OR 1=1";
        if (!run_query(db, injectedSQL, records)) return;
        dump_results(injectedSQL, records);
    }

    // query 2
    sql = "SELECT ID, NAME, PASSWORD FROM USERS WHERE ID=2";
    if (!run_query(db, sql, records)) return;
    dump_results(sql, records);

    // run query 2 with injection 5 times
    for (int i = 0; i < 5; ++i)
    {
        std::string injectedSQL = sql + " OR 2=2";
        if (!run_query(db, injectedSQL, records)) return;
        dump_results(injectedSQL, records);
    }

    // query 3
    sql = "SELECT ID, NAME, PASSWORD FROM USERS WHERE ID=3";
    if (!run_query(db, sql, records)) return;
    dump_results(sql, records);
    // run query with string injection
    {
        std::string injectedSQL = "SELECT ID, NAME, PASSWORD FROM USERS WHERE NAME='Fred' OR 'a'='a'";
        if (!run_query(db, injectedSQL, records)) return;
        dump_results(injectedSQL, records);
    }
}

// DO NOT CHANGE
int main()
{
    sqlite3* db = NULL;
    int return_code = 0;

    // open database in memory
    int result = sqlite3_open(":memory:", &db);
    if (result != SQLITE_OK)
    {
        std::cout << "Failed to connect to the database and terminating. ERROR=" << sqlite3_errmsg(db) << std::endl;
        return -1;
    }

    std::cout << "Connected to the database." << std::endl;

    // initialize our database
    if (!initialize_database(db))
    {
        std::cout << "Database Initialization Failed. Terminating." << std::endl;
        return_code = -1;
    }
    else
    {
        run_queries(db);
    }

    // close the connection if opened
    if (db != NULL)
    {
        sqlite3_close(db);
    }

    return return_code;
}



// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu
