from django.urls import path

from . import views

app_name = 'App'
urlpatterns = [
    path('accounts/login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('signup/?$', views.signup, name='signup'),
    path('', views.home, name='home'),
    path('users/?$', views.users, name='users'),

]
