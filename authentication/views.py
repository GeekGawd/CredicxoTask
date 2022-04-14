from rest_framework import generics, serializers, status, mixins
from authentication.models import *
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from authentication.serializers import AuthTokenSerializer, StudentSerializer,\
                                        UserSerializer, ChangePasswordSerializer,\
                                        TeacherSerializer
from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.exceptions import AuthenticationFailed
from django.http import Http404
import time, random
from django.core.mail import EmailMessage
from django.contrib.auth.hashers import check_password

# Create your views here.

def send_otp_email(email,subject):
    """A function that is used to send Forgot Password OTP to the user."""
    OTP.objects.filter(otp_email__iexact = email).delete()

    otp = random.randint(1000,9999)

    msg = EmailMessage(subject, f'The OTP for reset password is the following:\n {otp}' , 'swaad.info.contact@gmail.com', (email,))
    msg.content_subtype = "html"
    msg.send()

    time_created = int(time.time())

    OTP.objects.create(otp=otp, otp_email = email, time_created = time_created)

class CreateStudentView(generics.GenericAPIView, mixins.CreateModelMixin):
    """CBV-based Django View to create Students. 
        Can be accessed only by Superuser and Teachers
        
        Example JSON Format:
            {
            "email": "student6@gmail.com",
            "name": "Student",
            "phone_number": "1234567890",
            "dob": "2002-03-10",
            "address": "G-2, Sector-27",
            "subjects": ["Engineering Mathematics - 1", "ur mom"],
            "class": "CSE-1"
            }                                   """
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        request.data.update({"status": "Student"})
        if self.request.user.is_superuser or self.request.user.status == "Teacher":
            return super().create(request, *args, **kwargs)
        else:
            raise AuthenticationFailed("You are not authorized to make Student user.")

class CreateTeacherView(generics.GenericAPIView, mixins.CreateModelMixin):
    """CBV-based Django View to create Teachers. 
    Can be accessed only by Superuser.
    
    Example JSON Format:
        {
            "email": "teacher6@gmail.com",
            "name": "Student",
            "phone_number": "1234567891",
            "dob": "2002-03-10",
            "address": "G-2, Sector-27",
            "qualifications": ["B.Tech", "MBA"],
            "batches": ["CSE-1", "CSE-2", "CSE-3"],
            "subject": "Engineering Mathematics - 1"
        }                                   """
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        request.data.update({"status": "Teacher"})
        if self.request.user.is_superuser:
            return super().create(request, *args, **kwargs)
        else:
            raise AuthenticationFailed("You are not authorized to make Teacher user.")

class PasswordResetOTP(APIView):
    """A CBV-based Django view to send Reset Password OTP through email."""
    permission_classes = [AllowAny]

    def post(self, request):
        request_email = request.data.get("email", )

        try:
            user = User.objects.get(email__iexact = request_email)
        except: 
            return Response({"status" : "No such account exists"},status = status.HTTP_400_BAD_REQUEST)

        if user.is_active:
            send_otp_email(email = request_email,subject="[OTP] Password Change") 
            return Response({"status" : "OTP has been sent to your email."}, status = status.HTTP_200_OK)
        return Response({"status": "Please verify your account."}, status=status.HTTP_406_NOT_ACCEPTABLE)


class PasswordResetOTPConfirm(APIView):
    """A CBV=based Django view to confirm Reset Password OTP
         sent on the user email id."""
    permission_classes = [AllowAny]
    def post(self,request):
        data = request.data
        request_otp   = data.get("otp",)
        request_email = data.get("email",)

        if request_email:
            try:
                otp_instance = OTP.objects.get(otp_email__iexact = request_email)
                user = User.objects.get(email__iexact = request_email)
            except:
                raise Http404

            request_time = otp_instance.time_created
            email = otp_instance.otp_email
            current_time = int(time.time())

            if current_time - request_time > 300:
                return Response({"status" : "Sorry, entered OTP has expired.", "entered otp": request_otp},status = status.HTTP_408_REQUEST_TIMEOUT)

            if str(otp_instance.otp) != str(request_otp):
                 return Response({"status" : "Sorry, entered OTP doesn't match the sent OTP."},status = status.HTTP_409_CONFLICT)
            
            if (request_email != email):
                return Response({"status" : "Sorry, entered OTP doesn't belong to your email id."},status = status.HTTP_401_UNAUTHORIZED)
            
            otp_instance.delete()
            return Response({"status": "OTP Correct, proceed to change your password. "} , status=status.HTTP_200_OK)

        return Response({"status": "Please Provide an email address"},status = status.HTTP_400_BAD_REQUEST)

class ChangePassword(APIView):
    """A CBV-based Django View to Change Password,
     the old password cannot be the same as new password."""
    permission_classes = (AllowAny, )

    def patch(self, request, *args, **kwargs):
        request_email = request.data.get('email',)

        try:
            user = User.objects.get(email__iexact = request_email)
        except:
            return Response({"status": "Given User email is not registered." },
                                status=status.HTTP_403_FORBIDDEN)
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            if check_password(request.data.get("new_password",), user.password):
                return Response({"status": "New password cannot be the same as old password." },
                                status=status.HTTP_400_BAD_REQUEST)
            user.set_password(serializer.data.get("new_password"))
            user.save()
            return Response({"status": "Password Changed Successfully","token": user.tokens()},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED) 

class LoginAPIView(APIView):
    """A CBV-based Django view to enter login details
    get access token to access the API."""
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        request_email = request.data.get('email',)
        try:
            user1 = User.objects.get(email__iexact = request_email)
        except:
            return Response({'status':'User not registered'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = AuthTokenSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class StudentPersonalDetailView(generics.GenericAPIView, mixins.RetrieveModelMixin):
    """A CBV-based Django View. It is a GET based API so the user
    only needs to pass the token and detail will be shown.
    Only for Students"""
    permission_classes = [IsAuthenticated]
    serializer_class = StudentSerializer

    def get_object(self):
        student = Student.objects.get(user=self.request.user.id)
        return student
    
    def get(self, request, *args, **kwargs):
        try:
            return super().retrieve(request, *args, **kwargs)
        except ObjectDoesNotExist:
            return Response({"status": "Access Invalid"})

class TeacherPersonalDetailView(generics.GenericAPIView, mixins.RetrieveModelMixin):
    """A CBV-based Django View. It is a GET based API so the user
    only needs to pass the token and detail will be shown.
    Only for Teachers."""
    permission_classes = [IsAuthenticated]
    serializer_class = TeacherSerializer

    def get_object(self):
        teacher = Teacher.objects.get(user=self.request.user.id)
        return teacher
    
    def get(self, request, *args, **kwargs):
        try:
            return super().retrieve(request, *args, **kwargs)
        except ObjectDoesNotExist:
            return Response({"status": "Access Invalid"})
    

class ListStudentforTeacherView(generics.GenericAPIView, mixins.ListModelMixin):
    """A CBV-based Django View. It is used to list all the Students
    that are being taught by a Teacher."""
    permission_classes = [IsAuthenticated]
    serializer_class = StudentSerializer

    def get_queryset(self):
        teacher = self.request.user.teacher
        students = teacher.subject.student_set.all()
        return students


    def get(self, request, *args, **kwargs):
        user = request.user
        if user.status != "Teacher":
            raise AuthenticationFailed("You are not authorized to see student list for teachers.")
        return super().list(request, *args, **kwargs)

class ListAllStudent(generics.ListAPIView):
    """A CBV-based Django View. It is used to list all the Students.
    Accessible by Superuser and Teacher only."""
    queryset = Student.objects.all()
    serializer_class = StudentSerializer

    def get(self, request, *args, **kwargs):
        if request.user.is_superuser is True or request.user.status == "Teacher":
            return super().list(request, *args, **kwargs)
        raise AuthenticationFailed("You are not authorized to see Student List.")
    
class ListAllTeacher(generics.ListAPIView):
    """A CBV-based Django View. It is used to list all the Teachers
    Accessible only by Superuser."""
    queryset = Teacher.objects.all()
    serializer_class = TeacherSerializer

    def get(self, request, *args, **kwargs):
        if request.user.is_superuser is True:
            return super().list(request, *args, **kwargs)
        raise AuthenticationFailed("You are not authorized to see Teacher List.")
