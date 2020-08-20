<------------------------ admin.py ------------------------>

from __future__ import unicode_literals
from django.contrib.auth import get_user_model
from django.contrib import admin
User = get_user_model()

from .forms import CustomUserCreationForm
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
# from .forms import UserAdminCreationForm, UserAdminChangeForm

from .models import PhoneOTP
admin.site.register(PhoneOTP)


class CustomUserAdmin(BaseUserAdmin):

    add_form = CustomUserCreationForm
    # form = CustomUserChangeForm
    model = User
    list_display = ('username','email','phone', 'is_staff', 'is_active',)
    list_filter = ('username','email','phone','is_staff', 'is_active',)
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Permissions', {'fields': ('is_staff', 'is_active')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username','email','phone', 'password1', 'password2', 'is_staff', 'is_active')}
        ),
    )
    search_fields = ('email',)
    ordering = ('email',)

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(CustomUserAdmin, self).get_inline_instances(request, obj)


admin.site.register(User, CustomUserAdmin)

<------------------------ admin.py ------------------------>



<------------------------ forms.py ------------------------>

from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.contrib.auth.forms import UserCreationForm
from .models import User


class CustomUserCreationForm(UserCreationForm):

    class Meta:
        class Meta(UserCreationForm.Meta):
             model = User
             fields = ('username',)

<------------------------ forms.py ------------------------>



<------------------------ models.py ------------------------>

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, AbstractUser
from django.core.validators import RegexValidator
from django.db.models import Q
from django.db.models.signals import pre_save, post_save

from django.dispatch import receiver
# from rest_framework.authtoken.models import Token
from django.db.models.signals import post_save


import random
import os
import requests


class UserManager(BaseUserManager):
   
    def create_user(self, email, password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    CHOICES = (
        ("WOMEN_ENTREPRENEUR", 'Women Entrepreneur'),
        ("INFLUENCER", 'Influencer'),
        ("BUYER", 'Buyer'),
    )

    phone_regex = RegexValidator( regex = r'^\+?1?\d{9,10}$', message ="Phone number must be entered in the format +919999999999. Up to 10 digits allowed.")
    phone       = models.CharField('Phone',validators =[phone_regex], max_length=10, unique = True,null=True)
    REQUIRED_FIELD = ['username','phone']


    objects = UserManager()


class PhoneOTP(models.Model):
 
    phone_regex = RegexValidator( regex = r'^\+?1?\d{9,10}$', message ="Phone number must be entered in the format +919999999999. Up to 14 digits allowed.")
    phone       = models.CharField(validators =[phone_regex], max_length=17, unique = True)
    otp         = models.CharField(max_length=9, blank = True, null=True)
    count       = models.IntegerField(default=0, help_text = 'Number of otp_sent')
    validated   = models.BooleanField(default = False, help_text = 'If it is true, that means user have validate otp correctly in second API')
    otp_session_id = models.CharField(max_length=120, null=True, default = "")
    username    = models.CharField(max_length=20, blank = True, null = True, default = None )
    email       = models.CharField(max_length=50, null = True, blank = True, default = None) 
    password    = models.CharField(max_length=100, null = True, blank = True, default = None) 

    

    def __str__(self):
        return str(self.phone) + ' is sent ' + str(self.otp)    

<------------------------ models.py ------------------------>





<------------------------ views.py ------------------------>

from django.shortcuts import render
from django.http import HttpResponse
import http.client
# Create your views here.
import json
import requests
import ast

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status, generics
# from forms import UserForm
from .models import User, PhoneOTP
from django.shortcuts import get_object_or_404, redirect
import random
from .serializer import CreateUserSerializer, LoginSerializer
from knox.views import LoginView as KnoxLoginView
from knox.auth import TokenAuthentication
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated

from django.contrib.auth import login,logout

conn = http.client.HTTPConnection("2factor.in")


class ValidatePhoneSendOTP(APIView):

    def post(self, request, *args, **kwargs):
        phone_number = request.data.get('phone')
        password = request.data.get('password', False)
        username = request.data.get('username', False)
        email    = request.data.get('email', False)

        if phone_number:
            phone = str(phone_number)
            user = User.objects.filter(phone__iexact = phone)
            if user.exists():
                return Response({
                    'status' : False,
                    'detail' : 'Phone number already exists'
                })

            else:
                key = send_otp(phone)
                if key:
                    old = PhoneOTP.objects.filter(phone__iexact = phone)
                    if old.exists():
                        old = old.first()
                        count = old.count
                        if count > 10:
                            return Response({
                                'status' : False,
                                'detail' : 'Sending otp error. Limit Exceeded. Please Contact Customer support'
                            })

                        old.count = count +1
                        old.save()
                        print('Count Increase', count)

                        conn.request("GET", "https://2factor.in/API/R1/?module=SMS_OTP&apikey=1028fcd9-3158-11ea-9fa5-0200cd936042&to="+phone+"&otpvalue="+str(key)+"&templatename=WomenMark1")
                        res = conn.getresponse() 
                       
                        data = res.read()
                        data=data.decode("utf-8")
                        data=ast.literal_eval(data)
                        
                        
                        if data["Status"] == 'Success':
                            old.otp_session_id = data["Details"]
                            old.save()
                            print('In validate phone :'+old.otp_session_id)
                            return Response({
                                   'status' : True,
                                   'detail' : 'OTP sent successfully'
                                })    
                        else:
                            return Response({
                                  'status' : False,
                                  'detail' : 'OTP sending Failed'
                                }) 

                       


                    else:

                        obj=PhoneOTP.objects.create(
                            phone=phone,
                            otp = key,
                            email=email,
                            username=username,
                            password=password,
                        )
                        conn.request("GET", "https://2factor.in/API/R1/?module=SMS_OTP&apikey=1028fcd9-3158-11ea-9fa5-0200cd936042&to="+phone+"&otpvalue="+str(key)+"&templatename=WomenMark1")
                        res = conn.getresponse()    
                        data = res.read()
                        print(data.decode("utf-8"))
                        data=data.decode("utf-8")
                        data=ast.literal_eval(data)

                        if data["Status"] == 'Success':
                            obj.otp_session_id = data["Details"]
                            obj.save()
                            print('In validate phone :'+obj.otp_session_id)
                            return Response({
                                   'status' : True,
                                   'detail' : 'OTP sent successfully'
                                })    
                        else:
                            return Response({
                                  'status' : False,
                                  'detail' : 'OTP sending Failed'
                                })

                        
                else:
                     return Response({
                           'status' : False,
                            'detail' : 'Sending otp error'
                     })   

        else:
            return Response({
                'status' : False,
                'detail' : 'Phone number is not given in post request'
            })            



def send_otp(phone):
    if phone:
        key = random.randint(999,9999)
        print(key)
        return key
    else:
        return False

<------------------------ views.py ------------------------>


