import json
from django.http import HttpResponse, JsonResponse
from uuid import uuid4

from jwt import InvalidSignatureError

from .models import User, Task
from email_validator import validate_email, EmailNotValidError
import bcrypt
from config import jwt_secret
from django.views.decorators.csrf import csrf_exempt
import jwt

MAX_USERNAME_LENGTH = 30
MAX_PASSWORD_LENGTH = 60
MIN_USERNAME_LENGTH = 3
MIN_PASSWORD_LENGTH = 7


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def jwt_token_decoder(request):
    try:
        return jwt.decode(request.headers['X-Auth-Token'], jwt_secret, algorithms=['HS256'])['user_id']
    except InvalidSignatureError:
        return JsonResponse({"error": "Invalid JWT Signature"})
    except KeyError:
        return JsonResponse({"error": "JWT-Token not found."})
    except jwt.exceptions.DecodeError:
        return JsonResponse({"error": "JWT-Token Decode Error."})


@csrf_exempt
def user_login(request):
    """
        Login URL for Users. Returns JWT-Token encoded for authenticated user. JWT-Token should be passed to
        Login Required URLs to insure authenticity.

        Sample Input:
        {
            "user_id":"_sarveshJoshi22",
            "password": "SarveshJoshiPassword"
        }

        Sample Output:
        {
            "JWT_Token": "wow-this-is-a-jwt-token"
        }

    """
    if request.method == "POST":
        if request.body:
            try:
                received_data = json.loads(request.body.decode("utf-8"))
                username = received_data["user_id"]
                password = received_data["password"]
                try:
                    user = User.objects.get(user_id=username)
                    if bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
                        return JsonResponse(
                            {"JWT_Token": jwt.encode({'user_id': username}, jwt_secret, algorithm='HS256')})
                    else:
                        return JsonResponse({"error": "Wrong Password."})
                except User.DoesNotExist:
                    return JsonResponse({"error": "User with given credentials not found."})
            except KeyError:
                return JsonResponse({"error": "Required Credentials not found."})
        else:
            return JsonResponse({"error": "Data not found."})
    else:
        return JsonResponse({"error": "POST Data not found."})


@csrf_exempt
def user_signup(request):
    """
        Signup URL for Users to create a new account. Returns JWT-Token for successful creation of new user account.
        JWT-Token should be passed to every Login Required URLs to insure authenticity of the user.

        Sample Input:
        {
            "user_id":"_sarveshJoshi22",
            "password": "SarveshJoshiPassword",
            "email_id":"valid@gmail.com"
        }

        Sample Output :
        {
            "JWT_Token": "wow-this-is-a-jwt-token"
        }

    """
    if request.method == "POST":
        if request.body:
            try:
                received_data = json.loads(request.body.decode("utf-8"))
                username = received_data["user_id"]
                email_address = received_data["email_id"]
                password = received_data["password"]
                try:
                    user = User.objects.get(user_id=username)
                    return JsonResponse({"error": "Invalid Username / Username already exists."})
                except User.DoesNotExist:
                    try:
                        user = User.objects.get(email_address=email_address)
                        return JsonResponse({"error": "Invalid Email / Email already registered."})
                    except User.DoesNotExist:
                        pass
                try:
                    email_address = validate_email(email_address).email
                except EmailNotValidError:
                    return JsonResponse({"error": "Invalid Email Address."})
                if MIN_USERNAME_LENGTH > len(username) or len(username) > MAX_USERNAME_LENGTH:
                    return JsonResponse({"error": "Username's Length should be between {0} and {1}".format(
                        MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH)})
                if MIN_PASSWORD_LENGTH > len(password) or len(password) > MAX_PASSWORD_LENGTH:
                    return JsonResponse({"error": "Password's Length should be between {0} and {1}".format(
                        MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)})

                jwt_token = jwt.encode({'user_id': username}, jwt_secret, algorithm='HS256')
                save_this = User(user_uuid=uuid4(), user_id=username, password=hash_password(password),
                                 email_address=email_address)
                save_this.save()
                return JsonResponse({"JWT_Token": jwt_token})
            except KeyError:
                return JsonResponse({"error": "Required fields not found."})
        else:
            return JsonResponse({"error": "Data not found."})
    else:
        return JsonResponse({"error": "POST Request was expected."})


@csrf_exempt
def create_new_task(request):
    """
        View to create new task. Login Mandatory. JWT-Token should be sent with the request in a header named "X-Auth-Token".
        Any length of Title and Description is accepted.

        Sample Input:
        {
            "task_title":"Sample Task 1",
            "task_description":"Sample Task Description"
        }

        Sample Output:
        {
            "success": "Task added successfully."
        }
    """
    if request.method == "POST":
        if request.body:
            try:
                received_data = json.loads(request.body.decode("utf-8"))
                task_title = received_data["task_title"]
                task_description = received_data["task_description"]
                requesting_user_id = jwt_token_decoder(request=request)
                requesting_user = User.objects.get(user_id=requesting_user_id)

                save_this = Task(task_uuid=uuid4(), task_title=task_title, task_description=task_description,
                                 task_done=False, task_owner=requesting_user)
                save_this.save()
                return JsonResponse({"success": "Task added successfully."})
            except User.DoesNotExist:
                return JsonResponse({"error": "Requesting User not found."})
            except KeyError:
                return JsonResponse({"error": "Required fields not found."})
        else:
            return JsonResponse({"error": "Data not found."})
    else:
        return JsonResponse({"error": "POST Request was expected."})


@csrf_exempt
def delete_a_task(request, task_id):
    if request.method == "POST":
        try:
            requested_user_id = jwt_token_decoder(request)
            task = Task.objects.get(task_uuid=task_id)
            user = User.objects.get(user_id=requested_user_id)
            if task.task_owner_id != user.user_uuid:
                return JsonResponse({"error": "Permission Denied. The task doesn't belong to requesting user."})
            task.delete()
            return JsonResponse({"success": "Task deleted successfully."})
        except Task.DoesNotExist:
            return JsonResponse({"error": "Task doesn't exists."})
        except User.DoesNotExist:
            return JsonResponse({"error": "User doesn't exists."})
        except KeyError:
            return JsonResponse({"error": "Required Fields not found."})
    else:
        return JsonResponse({"error": "POST Data was expected."})


@csrf_exempt
def view_all_tasks(request):
    if request.method == "POST":
        try:
            requested_user_id = jwt_token_decoder(request)
            user = User.objects.get(user_id=requested_user_id)
            something = Task.objects.filter(task_owner=user.user_uuid)
            return_this = []
            for some in something:
                return_this.append({"task_id": some.task_uuid, "task_title": some.task_title, "task_description": some.task_description, "task_done": some.task_done})
            if len(return_this) > 1:
                return JsonResponse({"tasks": return_this})
            return JsonResponse({"message": "User got no tasks to show."})

        except User.DoesNotExist:
            return JsonResponse({"error": "Requested User not found."})


    else:
        return JsonResponse({"error": "POST request was expected."})


@csrf_exempt
def edit_a_task(request, task_id):
    if request.method == "POST":
        if request.body:
            try:
                received_data = json.loads(request.body.decode("utf-8"))
                task_title = received_data['task_title']
                task_description = received_data['task_description']
                requested_user_id = jwt_token_decoder(request)
                task = Task.objects.get(task_uuid=task_id)
                user = User.objects.get(user_id=requested_user_id)
                if task.task_owner_id != user.user_uuid:
                    return JsonResponse({"error": "Permission Denied. The task doesn't belong to requesting user."})
                task.task_title, task.task_description = task_title, task_description
                task.save()
                return JsonResponse({"success": "Task edited successfully."})
            except Task.DoesNotExist:
                return JsonResponse({"error": "Task doesn't exists."})
            except User.DoesNotExist:
                return JsonResponse({"error": "User doesn't exists."})
            except KeyError:
                return JsonResponse({"error": "Required fields not found."})
        else:
            return JsonResponse({"error": "Request Body was not found."})
    else:
        return JsonResponse({"error": "POST request was expected."})


@csrf_exempt
def done_a_task(request, task_id):
    if request.method == "POST":
        try:
            requested_user_id = jwt_token_decoder(request)
            task = Task.objects.get(task_uuid=task_id)
            user = User.objects.get(user_id=requested_user_id)
            if task.task_owner_id != user.user_uuid:
                return JsonResponse({"error": "Permission Denied. The task doesn't belong to requesting user."})
            task.task_done = not task.task_done
            task.save()
            if task.task_done:
                return JsonResponse({"success": "Task was marked Done."})
            return JsonResponse({"success": "Task was marked Undone."})
        except Task.DoesNotExist:
            return JsonResponse({"error": "Task doesn't exists."})
        except User.DoesNotExist:
            return JsonResponse({"error": "User doesn't exists."})
        except KeyError:
            return JsonResponse({"error": "Required fields not found."})
    else:
        return JsonResponse({"error": "POST request was expected."})
