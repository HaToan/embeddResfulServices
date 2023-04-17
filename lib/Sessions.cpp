#include <cassert>
#include <vector>
#include <stdlib.h>
#include <sstream>
#include <iostream>
#include <string>

#include "Sessions.h"
#include "Utils.h"

static char charset[] = "abcdeghijklmnpqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
#define CHARSET_SIZE (sizeof(charset)/sizeof(char))

namespace Mongoose
{
    Sessions::Sessions(const std::string &key, Controller *controller, Server *server)
        :
          AbstractRequestCoprocessor(controller, server),
          mGcDivisor(10),
          mGcCounter(0),
          mSessions(),
          mKey(key)
    {
    }

    Sessions::~Sessions()
    {
        std::map<std::string, Session *>::iterator it;
        for (it=mSessions.begin(); it!=mSessions.end(); it++)
        {
            delete (*it).second;
        }
    }

    std::string Sessions::getId(const std::shared_ptr<Request> &request, const std::shared_ptr<Response> &response)
    {

        if (request->hasCookie(mKey)) {
            return request->getCookie(mKey);
        } return "";
    }

   

    Session* Sessions::get(const std::shared_ptr<Request>& request, const std::shared_ptr<Response>& response)
    { 
        Session *session = nullptr;

        char newc[32] = {0};
        char hexdigest[SHA256_DIGEST_LENGTH * 2 + 1] = {0};

        
        for (int i=0; i<32; i++) {
            newc[i] = charset[rand()%CHARSET_SIZE];
        }

        Utils::sha256(newc, hexdigest);
        std::string id(hexdigest);
        response->setCookie(mKey, id);
        
        if (mSessions.find(id) != mSessions.end()) {
            session = mSessions[id];
        } else {
            if(mGcCounter < mGcDivisor){
                session = new Session();
                mSessions[id] = session;
                response->setCookie(mKey ,id);
            }else{
                response->setCookie(mKey, "0");
                session = NULL;
            }
            
        }

        return session;
    }

    std::string Sessions::getReqId(const std::shared_ptr<Request> &request, const std::shared_ptr<Response> &response)
    {

        if (request->hasCookie(mKey)) {
            return request->getCookie(mKey);
        } else {
            return "";
        }
    }

    bool Sessions::isExits(const std::shared_ptr<Request>& request, const std::shared_ptr<Response>& response)
    { 
        std::string id = getReqId(request, response);

        if (id.c_str() != "" && mSessions.find(id) != mSessions.end()) {
            return true;
        } 

        return false;
    }

    void Sessions::garbageCollect(int oldAge)
    {
        std::vector<std::string> deleteList;
        std::map<std::string, Session*>::iterator it;
        std::vector<std::string>::iterator vit;

        for (it=mSessions.begin(); it!=mSessions.end(); it++) {
            std::string name = (*it).first;
            Session *session = (*it).second;

            if (session->getAge() > oldAge) {
                delete session;
                deleteList.push_back(name);
            }
        }

        for (vit=deleteList.begin(); vit!=deleteList.end(); vit++) {
            mSessions.erase(*vit);
        }
    }

    bool Sessions::preProcess(const std::shared_ptr<Request> &request, const std::shared_ptr<Response> &response)
    {
        mGcCounter++;

        if (mGcCounter > mGcDivisor)
        {
            mGcCounter = 0;
            garbageCollect();
        }

        // get(request, response)->ping();
        return true;
    }
}
