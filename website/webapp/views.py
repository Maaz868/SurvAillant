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
from django.http import JsonResponse
from django.db.models import Sum

def home(request):
    return render(request, 'webapp/index.html')

def signup(request):
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
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            fname = user.username
            print(user,user.is_authenticated)
            return redirect('dashboard')
            # print(user.is_authenticated)
            # return render(request, 'webapp/index.html', {'fname': fname})
        else:
            messages.error(request, "Bad Credentials")
            return redirect('Signup-Signin/index.html')

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
    return render(request, 'network2.html')
    # template = loader.get_template('packet_monitor.html')
    # return HttpResponse(template.render())

def predictions(request):
    return render(request, 'predictions.html')


@login_required(login_url='signin') 
def admin_panel(request):

    unapproved_users =  CustomUser.objects.filter(is_user_approved=False)

    context={
        'unapproved_users':unapproved_users,
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

def alerts(request):
    return render(request, 'alerts.html')    


def landingpage(request):
    return render(request, 'landingpage.html')    


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
    return render(request, 'dash1.html', context)



def anomalyreports(request):
    anomalies = AnomalyPackets.objects.all()  # Query all anomalies (adjust the query based on your model structure)
    context = {'anomalies': anomalies}
    return render(request, 'anomalies.html', context)

def securityreports(request):
    security = SecurityPackets.objects.all()  # Query all anomalies (adjust the query based on your model structure)
    context = {'security': security}
    return render(request, 'security-threat.html', context)

