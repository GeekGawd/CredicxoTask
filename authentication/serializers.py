from rest_framework import serializers
from authentication.models import *
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from rest_framework.exceptions import NotAcceptable
import re


class AuthTokenSerializer(serializers.ModelSerializer):
    """The Serializer to Login the User and return the access and refresh tokens
        on inputting correct email and password."""
    email = serializers.CharField(required=True, error_messages={
                                  "required": "Email field may not be blank."})
    password = serializers.CharField(write_only=True, min_length=5)

    class Meta:
        model = User
        fields = ['email', 'access', 'refresh', 'password']

    def to_representation(self, instance):
        data = super(AuthTokenSerializer, self).to_representation(instance)
        user = User.objects.get(email=instance['email'])
        data['name'] = user.name
        data['user']=user.id
        return data

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        user = authenticate(
            request=self.context.get('request'),
            username=email,
            password=password
        )

        if not user:
            raise ValidationError(
                'Unable to authenticate with provided credentials')

        return {
            'email': user.email,
            'refresh': user.refresh,
            'access': user.access,
        }

class UserSerializer(serializers.ModelSerializer):
    """The Serializer to get User Details of Teacher and Students."""
    class Meta:
        model = User
        fields = ['email', 'name', 'dob', 'address', 'phone_number', 'status']

    def create(self, validated_data):
        """The function handles the creating of Teacher and Student."""
        user = super().create(validated_data)

        if user.status == "Student":
            subjects = self.initial_data.get('subjects')
            batches = self.initial_data.get('class')

            #Check if the object is a list instance or not. 
            #Otherwise if a string instance, the string will be unpacked.    
            if subjects is not None and isinstance(subjects, list): 
                try:
                    subjects_id = [Subject.objects.get(subjects=s) for s in subjects]
                    standard = Batch.objects.get(batch=batches)
                except ObjectDoesNotExist:
                    user.delete()
                    raise NotAcceptable("The entered details are invalid. Please check again.")

                student = Student.objects.create(user=user, batch=standard)
                student.subjects.add(*subjects_id)

        elif user.status == "Teacher":
            qualifications = self.initial_data.get('qualifications')
            batches = self.initial_data.get('batches')
            subject_data = self.initial_data.get('subject')
            subject, _ = Subject.objects.get_or_create(subjects=subject_data)

            #Check if the object is a list instance or not.
            #Otherwise if a string instance, the string will be unpacked.
            if None not in (qualifications, batches, subject) and isinstance(qualifications, list)\
            and isinstance(batches, list):

                try:
                    degrees = [Qualification.objects.get(degree=q).id for q in qualifications]
                    standards = [Batch.objects.get(batch=c).id for c in batches]
                except ObjectDoesNotExist:
                    user.delete()
                    raise NotAcceptable("Invalid Details. If adding non-existing details. Kindly add them from the Admin Panel.")

                teacher = Teacher.objects.create(user=user, subject=subject)
                teacher.qualification.add(*degrees)
                teacher.batches.add(*standards)

        return user
            

class StudentSerializer(serializers.ModelSerializer):
    """Student Serializer with nested UserSerializer for extra details"""
    student_details = UserSerializer(source='user')
    batch = serializers.SerializerMethodField()

    class Meta:
        model = Student
        fields = ['student_details', 'batch', 'roll_number']
    
    def get_batch(self, instance):
        return instance.batch.batch

class BatchSerializer(serializers.ModelSerializer):
    class Meta:
        model = Batch
        fields = '__all__'

class QualificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Qualification
        fields = '__all__'

class TeacherSerializer(serializers.ModelSerializer):
    """Student Serializer with nested UserSerializer, QualificationSerializer and
        BatchSerializer for extra details"""
    batches = BatchSerializer(many=True)
    qualification = QualificationSerializer(many=True)
    subject = serializers.SerializerMethodField()
    teacher_details = UserSerializer(source='user')

    class Meta:
        model = Teacher
        fields = ['teacher_details', 'batches','subject', 'qualification']

    def get_subject(self, instance):
        return str(instance.subject)

class ChangePasswordSerializer(serializers.Serializer):
    """The Change Password Serializer to change the password.
        It also has Regex Validation for the new password entered."""
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, password):
        if not re.findall('\d', password):
            raise ValidationError(
                ("The password must contain at least 1 digit, 0-9."),
                code='password_no_number',
            )
        if not re.findall('[A-Z]', password):
            raise ValidationError(
                ("The password must contain at least 1 uppercase letter, A-Z."),
                code='password_no_upper',
            )
        if not re.findall('[a-z]', password):
            raise ValidationError(
                ("The password must contain at least 1 lowercase letter, a-z."),
                code='password_no_lower',
            )

        return password