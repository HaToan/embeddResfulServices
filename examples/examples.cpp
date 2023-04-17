#ifndef _MSC_VER
#include <unistd.h>
#include <stdlib.h>
#else
#include <time.h>
#endif

#include <thread>
#include <chrono>
#include <cassert>
#include <sstream>
#include <signal.h>
#include <iostream>
#include <fstream>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <SQLiteCpp/SQLiteCpp.h>
#include <SQLiteCpp/VariadicBind.h>

#include "Server.h"
#include "Sessions.h"
#include "Controller.h"
#include "Utils.h"
#include <openssl/sha.h>

using namespace Mongoose;

volatile static bool running = false;

std::string getFullPath(std::string const &fileName) {
  std::string filePath(__FILE__);
  return filePath.substr(0, filePath.length() - std::string("examples.cpp").length()) + fileName;
}

std::string const dbFileName = getFullPath("../db/example.db3");

class HTTPController : public Controller, public Utils
{
    private:
    SQLite::Database    mDb;    ///< Database connection
    Sessions* s = NULL;
    // SQLite::Statement   mQuery;
    // Sessions mSessions;
    public: 
        HTTPController():mDb(dbFileName, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE){
            s = new Sessions();
            this->setSessions(s);
            this->registerCoprocessor(s);
        }

        virtual ~HTTPController()
        {
            delete s;
        }

        bool hello(const std::shared_ptr<Request>& req, const std::shared_ptr<Response>& res)
        {
            std::stringstream body;
            body << "Hello " << req->getVariable("name", "... what's your name ?\n");
            res->send(body.str());
            return true;
        }

        bool hello_delayed(const std::shared_ptr<Request>& req, const std::shared_ptr<Response>& res)
        {
            std::thread([=]
            {
                int duration = std::stoi(req->getVariable("duration", "3"));
                std::this_thread::sleep_for(std::chrono::seconds(duration));
                res->send("Hello after " + std::to_string(duration) + " seconds\n");
            }).detach();

            return true;
        }

        bool form(const std::shared_ptr<Request>& req, const std::shared_ptr<Response>& res)
        {
            std::stringstream responseBody;
            responseBody << "<form method=\"post\">" << std::endl;
            responseBody << "<input type=\"text\" name=\"test\" /><br >" << std::endl;
            responseBody << "<input type=\"submit\" value=\"Envoyer\" />" << std::endl;
            responseBody << "</form>" << std::endl;

            return res->send(responseBody.str());
        }

        bool formPost(const std::shared_ptr<Request>& req, const std::shared_ptr<Response>& res)
        {
            std::stringstream responseBody;
            responseBody << "Test=" << req->getVariable("test", "(unknown)");
            return res->send(responseBody.str());
        }

        bool forbid(const std::shared_ptr<Request>& req, const std::shared_ptr<Response>& res)
        {
            res->setCode(HTTP_FORBIDDEN);
            return res->send("403 forbidden demo");
        }

        bool exception(const std::shared_ptr<Request>& req, const std::shared_ptr<Response>& res)
        {
            throw std::string("Exception example");
        }


        bool upload(const std::shared_ptr<Request>& req, const std::shared_ptr<Response>& res)
        {
            std::stringstream responseBody;
            responseBody << "Your form variables: " << std::endl;

            for (const auto& variable: req->variables())
            {
                responseBody << variable.first << " : " << variable.second << std::endl;
            }

            return res->send(responseBody.str());
        }

        void setup()
        {
            std::cout << "Setup Router" << std::endl;
            // Hello demo
            addRoute("GET", "/hello", HTTPController, hello);
            addRoute("GET", "/hello_delayed", HTTPController, hello_delayed);

            // 403 demo
            addRoute("GET", "/403", HTTPController, forbid);

            //Generic register route
            registerRoute("POST", "/login", [=](const std::shared_ptr<Request>& req, const std::shared_ptr<Response>& res)
            {

                // check authen
                if(isAuth(req, res) == true) {
                    res->sendJson("{\"Status\": \"Success\"}");
                    return true;
                };

                // parse body
                rapidjson::Document doc;
                doc.Parse(req->body().c_str());

                if (doc.HasParseError()) {
                    std::cerr << "Error: failed to parse JSON document" << std::endl;
                    return false;
                }

                // check variable
                if (doc.HasMember("username") && doc["username"].IsString() && doc.HasMember("password") && doc["password"].IsString()) {
                    std::string username = doc["username"].GetString();
                    std::string password = doc["password"].GetString();

                    char hash_hexdegest[SHA256_DIGEST_LENGTH*2+1] = {0};
                    char text[SHA256_DIGEST_LENGTH] = {0};

                    for (int i = 0; i < password.length() &&  i < SHA256_DIGEST_LENGTH; i++) {
                            text[i] = password[i];
                    }
                    Utils::sha256(text, hash_hexdegest);

                    try{
                        // check username, passwd
                        SQLite::Statement query = SQLite::Statement(mDb, "SELECT * FROM users WHERE password = :password");
                        query.bind(":password", hash_hexdegest);
                        if(query.executeStep()){
                            // get and gen
                            if(this->setSessions(req, res) ==  NULL){
                                res->sendJson("{\"Status\": \"FULL\"}");
                                return false;
                            }
                            query.reset();
                            res->sendJson("{\"Status\": \"Success\"}");
                            return true;
                        }else{
                            res->sendJson("{\"Status\": \"Failse\"}");
                        }
                    }catch (std::exception& e)
                    {
                        std::cout << "SQLite exception: " << e.what() << std::endl;
                        return false; // unexpected error : exit the example program
                    }
                    // Reset the query to be able to use it again later
                }
            });

            registerRoute("POST", "/setups", [=](const std::shared_ptr<Request>& req, const std::shared_ptr<Response>& res)
            {
                rapidjson::Document doc;
                doc.Parse(req->body().c_str());

                if (doc.HasParseError()) {
                    std::cerr << "Error: failed to parse JSON document" << std::endl;
                    return false;
                }
                if (doc.HasMember("username") && doc["username"].IsString() && doc.HasMember("password") && doc["password"].IsString()) {
                    SQLite::Transaction transaction(mDb);
                    
                    try
                    {   
                        std::string username = doc["username"].GetString();
                        std::string password = doc["password"].GetString();


                        char hash_hexdegest[SHA256_DIGEST_LENGTH*2+1] = {0};
                        char text[SHA256_DIGEST_LENGTH] = {0};

                        for (int i = 0; i < password.length() &&  i < SHA256_DIGEST_LENGTH; i++) {
                                text[i] = password[i];
                        }
                        Utils::sha256(text, hash_hexdegest);

                        mDb.exec("DROP TABLE IF EXISTS users");
                        mDb.exec("CREATE TABLE users ( \
                            id INTEGER PRIMARY KEY AUTOINCREMENT, \
                            username TEXT NOT NULL UNIQUE, \
                            password TEXT NOT NULL, \
                            is_admin Interger NOT NULL)"
                        );
                        SQLite::Statement query = SQLite::Statement(mDb, "INSERT INTO users (username, password, is_admin) VALUES (:username, :password, :is_admin)");
                        query.bind(":username", username);
                        query.bind(":password", hash_hexdegest);
                        query.bind(":is_admin", 1);
                        query.exec();

                        // Reset the query to be able to use it again later
                        query.reset();
                        transaction.commit();
                    }catch (std::exception& e)
                    {
                        transaction.rollback();
                        std::cout << "SQLite exception: " << e.what() << std::endl;
                        return false; // unexpected error : exit the example program
                    }
                }
                rapidjson::StringBuffer buffer;
                buffer.Clear();
                rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                doc.Accept(writer);
                res->sendJson(buffer.GetString());
                return true;
            });
        }
};


int main()
{
    HTTPController httpControler;
    Server server("http://0.0.0.0:8080", "/home/xiot/dev/testmongoose/www", "#.html","./404.html");
    server.registerController(&httpControler);

    if (server.start())
    {
        std::cout << "Server started, routes:" << std::endl;
        httpControler.dumpRoutes();
        running = true;
    }
    
    while (running)
    {
        server.poll(1000);
    }

}
