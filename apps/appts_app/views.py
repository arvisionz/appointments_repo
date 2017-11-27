from django.shortcuts import render, HttpResponse, redirect
from datetime import date
from django.contrib import messages
from django.core.urlresolvers import reverse
from .models import Appointment
from ..login_and_reg_app.models import User

def index(request):
    if not 'user_id' in request.session:
        messages.error(request, 'must be logged in to continue')
        return redirect(reverse('login_stuff:my_index'))
    request.session['user_name']
    curr_user = User.objects.get(name=request.session['user_name'])
    context= {
        'myappts': Appointment.objects.filter(user=curr_user),
        'date_now': date.today()
    }
    return render(request, 'appts_app/dashboard.html', context)

def add(request):
    if len(request.POST['date']) < 1:
        messages.error(request, 'Date Field cannot be empty')
        return redirect('/dashboard')
    if len(request.POST['time']) < 1:
        messages.error(request, 'Time Field cannot be empty')
        return redirect('/dashboard')
    if len(request.POST['task']) < 1:
        messages.error(request, 'Task Field cannot be empty')
        return redirect('/dashboard')
    if Appointment.objects.filter(date=request.POST['date']).filter(time=request.POST['time']):
        messages.error(request, 'Date/time already in use')
        return redirect('/dashboard')

    else:
        curr_user = User.objects.get(name=request.session['user_name'])
        Appointment.objects.create(task=request.POST['task'], date=request.POST['date'], time=request.POST['time'], user=curr_user)
        return redirect('/dashboard')

def delete(request, id):
    Appointment.objects.filter(id=id).delete()
    return redirect('/dashboard')

def edit(request, id):
    context = {
        'appts': Appointment.objects.filter(id=id)
    }
    return render(request, 'appts_app/edit.html', context)

def update(request, id):
    if len(request.POST['task']) < 1:
        context = {
            'appts': Appointment.objects.filter(id=id)
        }
        messages.error(request, 'Task Field cannot be empty')
        return render(request, 'appts_app/edit.html', context)
    if len(request.POST['date']) < 1:
        context = {
            'appts': Appointment.objects.filter(id=id)
        }
        messages.error(request, 'Date Field cannot be empty')
        return render(request, 'appts_app/edit.html', context)
    if len(request.POST['time']) < 1:
        context = {
            'appts': Appointment.objects.filter(id=id)
        }
        messages.error(request, 'Time Field cannot be empty')
        return render(request, 'appts_app/edit.html', context)
    else:
        appt = Appointment.objects.get(id=id)
        appt.task = request.POST['task']
        appt.status = request.POST['status_options']
        appt.date = request.POST['date']
        appt.time = request.POST['time']
        appt.save()
        return redirect(reverse('appts_stuff:index'))
