from django.utils.deprecation import MiddlewareMixin


class LoggedInUserMiddleware(MiddlewareMixin):
    def process_template_response(self, request, response):
        if request.user.is_authenticated:
            response.context_data['logged_in_user_email'] = request.user.email
        return response
