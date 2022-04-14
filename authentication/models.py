from pickletools import read_uint1
from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager,PermissionsMixin
from django.forms import IntegerField
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError

# Create your models here.

USER_TYPE = (('Teacher', 'Teacher'), ('Student', 'Student'))

class UserManager(BaseUserManager):
    """Custom User Manager with the ability to create User and Superusers.
        It is very flexible with the details."""
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password):
        user = self.create_user(email, password)
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.save()
        return user


class User(AbstractBaseUser, PermissionsMixin):
    """Defining the User Model that will be used by
       both the Students and Teachers."""
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    dob = models.DateField(null=True)
    address = models.CharField(max_length=300, null=True)
    phone_number = models.CharField(max_length=10, unique = True,
                                    validators=[RegexValidator(regex='^[0-9]{10}$', message='Enter a 10 digit phone number.',),])
    status = models.CharField(choices=USER_TYPE, max_length=20, default="Student")
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    objects = UserManager()

    USERNAME_FIELD = 'email'

    def tokens(self):
        """This function returns the user access and refresh token."""
        refresh=RefreshToken.for_user(self)
        return{
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    def refresh(self):
        refresh=RefreshToken.for_user(self)
        return str(refresh)
    
    def access(self):
        refresh = RefreshToken.for_user(self)
        return str(refresh.access_token)

    def get_name(self):
        return str(self.name)

class Qualification(models.Model):
    """The Qualification Model for the Teachers."""
    degree = models.CharField(max_length=50)

    def __str__(self) -> str:
        return self.degree

class Batch(models.Model):
    """The Batch Model that specifies the batches the student study in
        and batches the Teachers teach in."""
    batch = models.CharField(max_length=50)

    def __str__(self) -> str:
        return self.batch

class Subject(models.Model):
    """The Subject Model defines what subjects the Students study and
    what subjects the Teacher teach."""
    subjects = models.CharField(max_length=50)

    def __str__(self) -> str:
        return self.subjects

class Teacher(models.Model):
    """The Teacher model which has is_active and is_staff permissions."""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE)
    qualification = models.ManyToManyField(Qualification)
    batches = models.ManyToManyField(Batch)

    def __str__(self) -> str:
        return f"Teacher->{self.user.name}"
    
    def clean(self) -> None:
        """The function to validate if the Teacher with status Teacher is being
        created as Teacher"""
        if self.user.status != "Teacher":
            raise ValidationError("The user model must be a Teacher instance.")

def roll_number_calculator():
    return Student.objects.all().count()+1

class Student(models.Model):
    """The Student which only has the is_active permission."""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    roll_number = models.CharField(max_length=50,unique=True, default=roll_number_calculator)
    batch = models.ForeignKey(Batch, on_delete=models.CASCADE)
    subjects = models.ManyToManyField(Subject)

    def __str__(self) -> str:
        return f"Student->{self.user.name}"
    
    def clean(self) -> None:
        """The function to validate if the Student with status Student is being
        created as Student"""
        if self.status != "Student":
            raise ValidationError("The user model must be a Student instance.")

class OTP(models.Model):
    """The OTP Model to send Forgot Password OTP."""
    otp = models.IntegerField()
    otp_email = models.EmailField()
    time_created = models.IntegerField()
    
    def __str__(self):
        return f"{self.otp_email} : {self.otp}"
        
    


