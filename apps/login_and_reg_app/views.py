from django.shortcuts import render, HttpResponse, redirect
from .models import User
from django.contrib import messages
from django.core.urlresolvers import reverse

def index(request):
    return render(request, 'login_and_reg_app/index.html')

def register(request):
    response_from_model = User.objects.register(request.POST)

    if response_from_model['status']:
        request.session['user_id'] = response_from_model['user'].id
        request.session['user_name'] = response_from_model['user'].name
        return redirect(reverse('appts_stuff:index'))

    else:
        for error in response_from_model['errors']:
            messages.error(request, error)
        return redirect(reverse('login_stuff:my_index'))
def login(request):
    response_from_model = User.objects.login(request.POST)
    if response_from_model['status']:
        request.session['user_id'] = response_from_model['user'].id
        request.session['user_name'] = response_from_model['user'].name
        return redirect(reverse('appts_stuff:index'))

    else:
        messages.error(request, response_from_model['errors'])
        return redirect(reverse('login_stuff:my_index'))

def success(request):
    if not 'user_id' in request.session:
        messages.error(request, 'must be logged in to continue')
        return redirect(reverse('login_stuff:my_index'))
    return redirect(reverse('appts_stuff:index'))

def logout(request):
    request.session.clear()
    return redirect(reverse('login_stuff:my_index'))
