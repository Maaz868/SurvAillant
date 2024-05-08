from django.shortcuts import redirect, render, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from scapy.all import sniff
from django.template import loader
from django.contrib.auth.hashers import make_password, check_password
from .models import CustomUser, PacketEntry, NetworkTraffic, ProtocolCount, SecurityTraffic, AnomalyPackets, SecurityPackets
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect, render
from django.http import JsonResponse
from django.db.models import Sum

def home(request):
    return render(request, 'Signup-Signin/index.html')



def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        renew_password = request.POST.get('renew_password')
        # print(current_password,new_password)
        # return redirect('admin_panel')
        current = CustomUser.objects.filter(id=request.user.id)[0]
        username = current.username

        user = authenticate(request, username=username, password=current_password)
        if user:
            if new_password != renew_password:
                messages.error(request, 'Passwords do not match.')
                return redirect('admin_panel')
            else:
                
                user.set_password(new_password)
                user.save()
                login(request, user)
                unapproved_users =  CustomUser.objects.filter(is_user_approved=False)
                # print(unapproved_users)
                current_user = CustomUser.objects.filter(id=request.user.id)

                # print(current_user[1])
                context={
                    'unapproved_users':unapproved_users,
                    'current_user':current_user[0],
                }
                
                return redirect('dashboard')
                messages.success(request, 'Password changed successfully.')
                # return redirect('admin_panel')
                # return render(request, 'users-profile.html',context=context)
        
                
        else:
            messages.error(request, 'The old password entered is incorrect.')   
            return redirect('admin_panel')
        # print("user: ",username)
        # return redirect('admin_panel')

    return render(request, 'users-profile.html')
        
        # # Add your password change logic here
        
        # messages.success(request, 'Password changed successfully.')
        # return redirect('success_url')  # Redirect to a success page after password change



def signup(request):
    try:
        logout(request)
    except:
        pass

    if request.method == "POST":
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        if password != confirm_password:
            return render(request, 'Signup-Signin/index.html', {'error': 'Passwords do not match'})

        if CustomUser.objects.filter(username=username).exists():
            return render(request, 'Signup-Signin/index.html', {'error': 'User already exists'})

        user = CustomUser.objects.create_user(username=username, email=email, password=password,is_admin=True)
        # login(request, user)
        return redirect('signin')  # Adjust the URL name accordingly

    return render(request, 'Signup-Signin/index.html')


def signin(request):
    try:
        logout(request)
    except:
        pass
    
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            fname = user.username
            # print(user,user.is_authenticated)
            return redirect('dashboard')
            # print(user.is_authenticated)
            # return render(request, 'webapp/index.html', {'fname': fname})
        else:
            messages.error(request, "Bad Credentials")
            return redirect('signin')

    return render(request, 'Signup-Signin/index.html')

@login_required(login_url='signin')
def trial(request):
    # print(request.user)
    return render(request, 'trial.html')

def signout(request):
    logout(request)
    messages.success(request,"You've logged out")
    return render(request, 'landingpage.html')

@login_required(login_url='signin')
def sniff_packets(request):
    return render(request, 'network2.html')
    # template = loader.get_template('packet_monitor.html')
    # return HttpResponse(template.render())

@login_required(login_url='signin')
def predictions(request):
    return render(request, 'predictions.html')


@login_required(login_url='signin') 
def admin_panel(request):

    unapproved_users =  CustomUser.objects.filter(is_user_approved=False)
    # print(unapproved_users)
    current_user = CustomUser.objects.filter(id=request.user.id)

    # print(current_user[1])
    context={
        'unapproved_users':unapproved_users,
        'current_user':current_user[0],
    }
    return render(request, 'users-profile.html',context)

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

@login_required(login_url='signin')
def alerts(request):
    return render(request, 'alerts.html')    


def landingpage(request):
    try:
        logout(request)
    except:
        pass
    
    return render(request, 'landingpage.html')    

@login_required(login_url='signin')
def dashboard(request):
    
    all_entries = NetworkTraffic.objects.all()
    all_entries2 = SecurityTraffic.objects.all()

    # Calculate total counts
    total_anomaly_count = sum(entry.anomaly_packets for entry in all_entries)
    total_normal_count = sum(entry.normal_packets for entry in all_entries)

    # Calculate total counts
    total_security_count = sum(entry.security_packets for entry in all_entries2)
    total_normal_count2 = sum(entry.normal_packets for entry in all_entries2)

    
    # Fetch the last 12 entries from the database
    entries = PacketEntry.objects.order_by('-timestamp')[:12]
    labels = [str(entry.timestamp) for entry in entries]
    chart_data = [entry.number_of_packets for entry in entries]

    protocol_counts = ProtocolCount.objects.aggregate(
        tcp_count=Sum('tcp_count'),
        udp_count=Sum('udp_count'),
        modbus_count=Sum('modbus_count'),
        mqtt_count=Sum('mqtt_count'),
        others_count=Sum('others_count'),
    )

    # Pass the data to the template
    context = {'labels': labels, 'chart_data': chart_data, 
               'total_anomaly_count': total_anomaly_count,
                'total_normal_count': total_normal_count,
                'protocol_counts': protocol_counts,
                'total_security_count': total_security_count,
                'total_normal_count1': total_normal_count2,
                }
    return render(request, 'dash.html', context)


@login_required(login_url='signin')
def anomalyreports(request):
    anomalies = AnomalyPackets.objects.all()  # Query all anomalies (adjust the query based on your model structure)
    context = {'anomalies': anomalies}
    return render(request, 'anomalies.html', context)

@login_required(login_url='signin')
def securityreports(request):
    security = SecurityPackets.objects.all()  # Query all anomalies (adjust the query based on your model structure)
    context = {'security': security}
    return render(request, 'security-threat.html', context)



# from django.contrib.auth.hashers import check_password
