#include <string>
#include <iostream>
#include <algorithm>

#include <mongoose.h>

#include "Controller.h"
#include "Request.h"
#include "Response.h"
#include "Server.h"
#include "Utils.h"
#include "Mutex.h"

using namespace std;
using namespace Mongoose;

namespace Mongoose
{

static struct mg_http_serve_opts sHttpOptions = {0};


Server::Server(const char *address, const char *documentRoot, const char *ssi_patterm, const char *page404): mIsRunning(false)
{
    memset(&sHttpOptions, 0, sizeof(sHttpOptions));
    setBindAddress(address);
    setDocumentRoot(documentRoot);
    sHttpOptions.root_dir = documentRoot;
    sHttpOptions.ssi_pattern = ssi_patterm;
    sHttpOptions.page404 = page404;
}

Server::~Server()
{
    stop();
}

bool Server::start()
{
    mManager = new (struct mg_mgr);  
    mg_log_set(MG_LL_DEBUG);
    mg_mgr_init(mManager);

    // set Controler for Server
    setUserData(this);

    if (!mIsRunning && mManager->userdata)
    {
        mConnection = mg_http_listen(mManager, mBindAddress.c_str(), ev_handler, NULL);  // Create HTTP listener
        //mConnection = mg_http_listen(mManager, s_https_addr, ev_handler, this);  // HTTPS listener
        if(mConnection){
            mIsRunning = true;
        }
    }

    if (mConnection == nullptr)
    {
        mg_mgr_free(mManager);
        mIsRunning = false;
        delete mManager;
        mManager = nullptr;
        std::cerr << "Error, unable to start server" << std::endl;
    }
    return mIsRunning;
}

void Server::setUserData(void *userdata){
    mManager->userdata = userdata;
}

bool Server::handles(const string &method, const string &url)
{
    for (auto controller: mControllers)
    {
        if (controller->handles(method, url))
        {
            return true;
        }
    }
    return false;
}

void Server::ev_handler(struct mg_connection *c, int ev, void *ev_data, void *fn_data)
{
    if (ev == MG_EV_ACCEPT && fn_data != NULL) {

        //Hooks accpet connect

    } else if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        assert(server);
        Server  *server = static_cast<Server*>(c->mgr->userdata);
        
        if (server->requiresBasicAuthentication())
        {
                char username[256] = {0};
                char password[256] = {0};
                // get username, passwd from user
                mg_http_creds(hm, username, 256, password, 256);
                if ( server->basicAuthUsername() != username  || server->basicAuthPassword() != password)
                {
                    mg_printf(c,
                            "HTTP/1.0 401 Unauthorized\r\n"
                            "WWW-Authenticate: Basic realm=\"Failed!\"\r\n"
                            "Content-Length: 0\r\n\r\n");
                    c->is_resp |= 0;
                    return;
                }
        }

        // Check dispatch
        if(server->handles(std::string(hm->method.ptr, hm->method.len), std::string(hm->uri.ptr, hm->uri.len))){
            auto request = std::make_shared<Request>(c, hm);
            auto response = std::make_shared<Response>(c);

            server->mCurrentRequests[c] = request;
            server->mCurrentResponses[c] = response;

            server->handleRequest(request, response);
        } else {
            mg_http_serve_dir(c, hm, &sHttpOptions);
        }
    }
    (void) fn_data;
}

bool Server::handleRequest(const std::shared_ptr<Request> &request, const std::shared_ptr<Response> &response)
{
    mRequests++;

    bool result = false;

    for (auto controller: mControllers)
    {
        if (controller->handles(request->method(), request->url()))
        {
            try
            {
                result = controller->handleRequest(request, response);

            }
            catch(...)
            {
                result = false;
            }

            if (response->isValid() && !result)
            {
                response->sendError("Server error trying to handle the request");
            }
            break;
        }
    }

    return result;
}


void Server::poll(int duration)
{
    if (mIsRunning)
    {
        mg_mgr_poll(mManager, duration);
    }
}

void Server::stop()
{
    if (mIsRunning)
    {
        mg_mgr_free(mManager);
        delete mManager;
        mManager = nullptr;
        mIsRunning = false;
    }
}

void Server::registerController(Controller *controller){
    controller->setServer(this);
    // controller->setSessions(&sessions);
    controller->setup();
    mControllers.push_back(controller);
}

void Server::deregisterController(Controller *controller){
    auto it = std::find(mControllers.begin(), mControllers.end(), controller);

    if (it != mControllers.end())
    {
        mControllers.erase(it);
    }
}

std::string Server::documentRoot() const{
    return mDocumentRoot;
}

void Server::setDocumentRoot(const std::string& root){
    mDocumentRoot = root;
    sHttpOptions.root_dir = mDocumentRoot.c_str();
}

void Server::setBindAddress(const string &address)
{
    mBindAddress = address;
}

std::string Server::bindAddress() const{
    return mBindAddress;
}

// authen
string Server::basicAuthUsername() const
{
    return mBasicAuthUsername;
}

void Server::setBasicAuthUsername(const string &user)
{
    mBasicAuthUsername = user;
}

string Server::basicAuthPassword() const
{
    return mBasicAuthPassword;
}

void Server::setBasicAuthPassword(const string &password)
{
    mBasicAuthPassword = password;
}

bool Server::requiresBasicAuthentication() const
{
    return mBasicAuthUsername.size() > 0 && mBasicAuthPassword.size() > 0;
}

string Server::ipAccessControlList() const
{
    return mIpAccessControlList;
}

void Server::setIpAccessControlList(const string &acl)
{
    mIpAccessControlList = acl;
}

}