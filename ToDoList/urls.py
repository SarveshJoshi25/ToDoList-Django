from django.urls import path, include
from . import views

urlpatterns = [
    path("", views.user_login, name="login"),
    path("login/", views.user_login, name="login"),
    path("signup/", views.user_signup, name="signup"),
    path("newtask/", views.create_new_task, name="create_new_task"),
    path("deletetask/<str:task_id>", views.delete_a_task, name="delete_a_task"),
    path("mytasks/", views.view_all_tasks, name="view_all_tasks"),
    path("edittask/<str:task_id>", views.edit_a_task, name="edit_a_task"),
    path("markdone/<str:task_id>", views.done_a_task, name="done_a_task")
]
