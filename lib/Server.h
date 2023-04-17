#ifndef _MONGOOSE_SERVER_H
#define _MONGOOSE_SERVER_H

#include <iostream>
#include <map>
#include <memory>
#include <vector>
#include <string>

#include "Mutex.h"
#include <Sessions.h>

struct mg_connection;
struct mg_mgr;
/**
 * Wrapper for the Mongoose server
 */
namespace Mongoose
{
class Controller;
class Request;
class Response;
class Server
{
public:
    Server(const char *bindAddress = "http://0.0.0.0:8000", const char *documentRoot = "./www",  const char *ssi_patterm = NULL, const char *page404 = NULL);
    virtual ~Server();

    bool isRunning() const;

    bool start();

    void poll(int duration);

    void stop();

    void registerController(Controller *c);
    void deregisterController(Controller *c);
    bool handles(const std::string& method, const std::string& url);

    std::string documentRoot() const;
    void setDocumentRoot(const std::string& root);
    // void setIndexFiles(const string &files)
    std::string bindAddress() const;
    void setBindAddress(const std::string& address);

    //
    std::string basicAuthUsername() const;
    void setBasicAuthUsername(const std::string& user);

    std::string basicAuthPassword() const;
    void setBasicAuthPassword(const std::string& password);

    bool requiresBasicAuthentication() const;

    std::string ipAccessControlList() const;
    void setIpAccessControlList(const std::string& acl);

    protected:
        Sessions sessions;

    private:
        bool mIsRunning;
        struct mg_mgr *mManager{nullptr};
        struct mg_connection *mConnection{nullptr};
        static void ev_handler(struct mg_connection *c, int ev, void *ev_data, void *fn_data);

        // httpoptions
        std::string ssi_patterm;
        std::string page404;

        void setUserData(void *);
        bool handleRequest(const std::shared_ptr<Request>& request, const std::shared_ptr<Response>& response);

        //Internals
        std::map<struct mg_connection*, std::shared_ptr<Request>> mCurrentRequests;
        std::map<struct mg_connection*, std::shared_ptr<Response>> mCurrentResponses;
        std::vector<Controller *> mControllers;

        // Bind options
        std::string mBindAddress;
        bool mAllowMultipleClients;

        // Http Options
        std::string mDocumentRoot;
        std::string mIndexFiles;

        // Statistics
        int mRequests{0};
        int mStartTime{0};

        //authen
        std::string mBasicAuthUsername;
        std::string mBasicAuthPassword;
        std::string mIpAccessControlList;

        std::string mTmpDir;
    };
}
#endif
