import json
from django.http import HttpResponse, JsonResponse
from uuid import uuid4
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
                        return JsonResponse({"JWT_Token": jwt.encode({'user_id': username}, jwt_secret, algorithm='HS256')})
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

    return JsonResponse({"message": "You are on Create New Task Page (Login Mandatory)."})


def delete_a_task(request):
    return JsonResponse({"message": "You are on deleting a task page (Login Mandatory)."})


def view_all_tasks(request):
    return JsonResponse({"message": "You are on view all tasks page (Login Mandatory)."})
