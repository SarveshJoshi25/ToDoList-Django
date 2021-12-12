from django.urls import path, include
from . import views

urlpatterns = [
    path("", views.user_login, name="login"),
    path("login/", views.user_login, name="login"),
    path("signup/", views.user_signup, name="signup"),
    path("newtask/", views.create_new_task, name="create_new_task"),
    path("deletetask/", views.delete_a_task, name="delete_a_task"),
    path("mytasks/", views.view_all_tasks, name="view_all_tasks")
]
