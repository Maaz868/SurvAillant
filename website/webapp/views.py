from django.shortcuts import redirect, render, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from scapy.all import sniff
from django.template import loader
from django.contrib.auth.hashers import make_password, check_password
from .models import CustomUser
from django.contrib.auth.decorators import login_required



def home(request):
    return render(request, 'webapp/index.html')

def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        if password != confirm_password:
            return render(request, 'webapp/signup.html', {'error': 'Passwords do not match'})

        if CustomUser.objects.filter(username=username).exists():
            return render(request, 'webapp/signup.html', {'error': 'User already exists'})

        user = CustomUser.objects.create_user(username=username, email=email, password=password,is_admin=True)
        # login(request, user)
        return redirect('signin')  # Adjust the URL name accordingly

    return render(request, 'webapp/signup.html')


def signin(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            fname = user.username
            print(user,user.is_authenticated)
            return redirect('home')
            # print(user.is_authenticated)
            # return render(request, 'webapp/index.html', {'fname': fname})
        else:
            messages.error(request, "Bad Credentials")
            return redirect('home')

    return render(request, 'Signup-Signin/index.html')

@login_required(login_url='signin')
def trial(request):
    # print(request.user)
    return render(request, 'trial.html')

def signout(request):
    logout(request)
    messages.success(request,"You've logged out")
    return redirect('home')

def sniff_packets(request):
    return render(request, 'packet_monitor.html')
    # template = loader.get_template('packet_monitor.html')
    # return HttpResponse(template.render())

def predictions(request):
    return render(request, 'predictions.html')


@login_required(login_url='signin') 
def admin_panel(request):
#     if request.method == "POST":
#         users_to_approve = CustomUser.objects.filter(id=user_id)

#         if users_to_approve.exists():
#             # If user is found, mark them as approved
#             user = users_to_approve.first()
#             user.is_user_approved = True
#             user.save()
#         else:
#             # Handle the case where the user with the specified id is not found
#             return render(request, 'trial.html')  # Create this template


    unapproved_users =  CustomUser.objects.filter(is_user_approved=False)

    context={
        'unapproved_users':unapproved_users,
    }
    return render(request, 'admin_panel.html',context)

@login_required(login_url='signin') 
def approve_user(request, user_id):
    # Filter users
    users_to_approve = CustomUser.objects.filter(id=user_id)

    if users_to_approve.exists():
        user = users_to_approve.first()
        user.is_user_approved = True
        user.save()
        # return redirect('admin_panel')
    else:
        # handle the case where the user with the specified id is not found
        return render(request, 'trial.html')  

    return redirect('admin_panel')


