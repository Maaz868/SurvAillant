from django.shortcuts import render, redirect
from django.urls import reverse

class AdminMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        path = request.path
        # print(user)
        print(path)

        admin_paths=['/admin-panel']

        if path in admin_paths and (not user.is_authenticated or not user.is_admin):
            # return render(request, 'wait_for_approval.html')
            return redirect('home')
        return self.get_response(request)
    

class WaitingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        path = request.path
        # print(user)

        paths=['/sniff','/predictions','/trial']

        if user.is_authenticated and not user.is_user_approved and path in paths:
            return render(request, 'wait_for_approval.html')  # Create this template

        return self.get_response(request)
    
