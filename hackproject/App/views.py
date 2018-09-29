from django.shortcuts import render, redirect, get_object_or_404
from django.utils import dateparse
from django.core.exceptions import PermissionDenied
from django.contrib.admin.models import LogEntry
from django.contrib.auth import logout, login, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import HttpResponse
from django.db.models import Max
from . import form_utilities
from .form_utilities import *
from . import checks
from .models import *
import datetime
import json
import time

@login_required
def add_group(request):
    message = None
    if request.POST:
        group, message = handle_add_group_form(request, request.POST)
        if group:
            addition(request, group)
            return redirect('health:conversation', group.pk)
    return messages(request, error=message)


def handle_add_group_form(request, body):
    name = body.get('name')
    recipient_ids = body.getlist('recipient')
    message = body.get('message')

    if not all([name, recipient_ids, message]):
        return None, "All fields are required."
    if not [r for r in recipient_ids if r.isdigit()]:
        return None, "Invalid recipient."
    group = MessageGroup.objects.create(
        name=name
    )
    try:
        ids = [int(r) for r in recipient_ids]
        recipients = User.objects.filter(pk__in=ids)
    except User.DoesNotExist:
        return None, "Could not find user."
    group.members.add(request.user)
    for r in recipients:
        group.members.add(r)
    group.save()
    Message.objects.create(sender=request.user, body=message,
                           group=group, date=timezone.now())
    return group, None


def login_view(request):
    """
    Presents a simple form for logging in a user.
    If requested via POST, looks for the username and password,
    and attempts to log the user in. If the credentials are invalid,
    it passes an error message to the context which the template will
    render using a Bootstrap alert.

    :param request: The Django request object.
    :return: The rendered 'login' page.
    """
    context = {'navbar':'login'}
    if request.POST:
        user, message = login_user_from_form(request, request.POST)
        if user:
            return redirect('App:home')
        elif message:
            context['error_message'] = message
    return render(request, 'App/login.html', context)

def login_user_from_form(request, body):
    """
    Validates a user's login credentials and returns a tuple
    containing either a valid, logged-in user or a failure
    message.

    Checks if all fields were supplied, then attempts to authenticate,
    then checks if the 'remember' checkbox was checked. If it was, sets
    the cookie's expiration to 0, meaning it will be invalidated when the
    session ends.

    :param request: The Django request object.
    :return: The rendered 'login' page.
    """
    email = body.get("email")
    password = body.get("password")
    if not all([email, password]):
        return None, "You must provide an email and password."
    email = email.lower()  # all emails are lowercase in the database.
    user = authenticate(username=email, password=password)
    remember = body.get("remember")
    if user is None:
        return None, "Invalid username or password."
    login(request, user)
    if remember is not None:
        request.session.set_expiry(0)
    return user, None

# Create your views here.
def logout_view(request):
    """
    Logs the user out and redirects the user to the login page.
    :param request: The Django request.
    :return: A 301 redirect to the login page.
    """
    logout(request)
    return redirect('App:login')

def users(request):

    clients = request.user
    context = {
        'navbar': 'users',
        'clients': clients,
    }
    return render(request, 'App/users.html', context)

@login_required
def home(request):
    context = {
        'navbar': 'home',
        'user': request.user,
    }
    return render(request, 'App/home.html', context)


def signup(request):
    """
    Presents a simple signup page with a form of all the required
    fields for new users.
    Uses the full_signup_context function to populate a year/month/day picker
    and, if the user was created successfully, prompts the user to log in.
    :param request:
    :return:
    """
    context = full_signup_context(None)
    context['is_signup'] = True
    if request.POST:
        user, message = handle_user_form(request, request.POST)
        if user:
            addition(request, user)
            if request.user.is_authenticated():
                return redirect('App:signup')
            else:
                return redirect('App:login')
        elif message:
            context['error_message'] = message
    context['navbar'] = 'signup'
    return render(request, 'App/signup.html', context)


def full_signup_context(user):
    """
    Returns a dictionary containing valid years, months, days, hospitals,
    and groups in the database.
    """
    return {
        "year_range": reversed(range(1900, datetime.date.today().year + 1)),
        "day_range": range(1, 32),
        "months": [
            "Jan", "Feb", "Mar", "Apr",
            "May", "Jun", "Jul", "Aug",
            "Sep", "Oct", "Nov", "Dec"
        ]
    }


def handle_user_form(request, body, user=None):
    """
    Creates a user and validates all of the fields, in turn.
    If there is a failure in any validation, the returned tuple contains
    None and a failure message.
    If validation succeeds and the user can be created, then the returned tuple
    contains the user and None for a failure message.
    :param body: The POST body from the request.
    :return: A tuple containing the User if successfully created,
    or a failure message if the operation failed.
    """
    password = body.get("password")
    first_name = body.get("first_name")
    last_name = body.get("last_name")

    username = body.get("username")
    email = body.get("email")
    group = body.get("group")
    client_group= Group.objects.get(name='Client')
    group = Group.objects.get(pk=int(group)) if group else client_group
    is_client = group == client_group
    phone = form_utilities.sanitize_phone(body.get("phone_number"))
    month = int(body.get("month"))
    day = int(body.get("day"))
    year = int(body.get("year"))
    date = datetime.date(month=month, day=day, year=year)

    if not all([first_name, last_name, email, phone,
                month, day, year, date]):
        return None, "All fields are required."
    email = email.lower()  # lowercase the email before adding it to the db.
    if not form_utilities.email_is_valid(email):
        return None, "Invalid email."

    if User.objects.filter(email=email).exists() or User.objects.filter(username=username).exists():
        return None, "A user with that email/username already exists."
    user = User.objects.create_user(username, email=email,
            password=password, date_of_birth=date, phone_number=phone,
            first_name=first_name, last_name=last_name)
    if user is None:
        return None, "We could not create that user. Please try again."

    request.user = user
    addition(request, user)
    group.user_set.add(user)
    return user, None
