#ifndef _MONGOOSE_CONTROLLER_H
#define _MONGOOSE_CONTROLLER_H

#include <functional>
#include <map>
#include <memory>
#include <vector>
#include <string>
#include <Sessions.h>

//Helper define for binding class methods
#define addRoute(httpMethod, httpRoute, className, methodName) \
    registerRoute(httpMethod, httpRoute, std::bind(&className::methodName, this, std::placeholders::_1, std::placeholders::_2))

#define addRouteResponse(httpMethod, url, controllerType, method, responseType) \
    registerRoute(httpMethod, url, new RequestHandler<controllerType, responseType>(this, &controllerType::method ));

namespace Mongoose
{
    class AbstractRequestCoprocessor;
    class Server;
    class Request;
    class Response;

    typedef std::function<bool(const std::shared_ptr<Request>&, const std::shared_ptr<Response>&)> RequestHandler;

    class Controller
    {
        public:
            Controller(Server *server = nullptr, Sessions *session = nullptr);
            virtual ~Controller();

            virtual void setup();

            virtual bool preProcess(const std::shared_ptr<Request>& request, const std::shared_ptr<Response>& response);

            virtual bool process(const std::shared_ptr<Request>& request, const std::shared_ptr<Response>& response);

            virtual bool postProcess(const std::shared_ptr<Request>& request, const std::shared_ptr<Response>& response);

            virtual bool handles(const std::string& method, const std::string& url) const;

            virtual bool handleRequest(const std::shared_ptr<Request>& request, const std::shared_ptr<Response>& response);

            // virtual Response *serverInternalError(string message);
            
            Server* server() const;

            void setServer(Server *server);

            std::string prefix() const;

            void setPrefix(const std::string& prefix);

            void registerCoprocessor(AbstractRequestCoprocessor* preprocessor);

            void deregisterCoprocessor(AbstractRequestCoprocessor* preprocessor);

            void registerRoute(std::string httpMethod, std::string httpRoute, RequestHandler handler);

            void deregisterRoute(std::string httpMethod, std::string httpRoute);

            void dumpRoutes() const;

            std::vector<std::string> urls() const;

            void setSessions(Sessions *sessions);
            Sessions* sessions() const;
            bool isAuth(const std::shared_ptr<Request> &request, const std::shared_ptr<Response> &response);
            Session* setSessions(const std::shared_ptr<Request> &request, const std::shared_ptr<Response> &response);

        protected:
            Sessions *mSessions;
            Server *mServer;
            std::string mPrefix;
            std::map<std::string, RequestHandler> mRoutes;
            std::vector<std::string> mUrls;
            std::vector<AbstractRequestCoprocessor*> mCoprocessors;
    };
}

#endif
