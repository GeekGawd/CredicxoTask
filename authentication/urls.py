from django.urls import path
from authentication import views
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    path('student/login/',views.LoginAPIView.as_view(), name='login'),

    path('student/personal/', views.StudentPersonalDetailView.as_view(), name='studentview'),

    path('teacher/personal/', views.TeacherPersonalDetailView.as_view(), name='teacherview'),

    path('student/list/', views.ListStudentforTeacherView.as_view(), name='liststudent'),

    path('student/create/', views.CreateStudentView.as_view(), name='createuser'),

    path('teacher/create/', views.CreateTeacherView.as_view(), name='createuser'),

    path('reset/', views.PasswordResetOTP.as_view(), name='passwordreset'),

    path('reset/verify/', views.PasswordResetOTPConfirm.as_view(), name='passwordresetconfirmation'),

    path('changepsw/', views.ChangePassword.as_view(), name='loggedinuser'),

    path('student/list/', views.ListAllStudent.as_view(), name='allstudentlist'),

    path('teacher/list/', views.ListAllTeacher.as_view(), name='allteacherlist'),

    path('token/refresh/', TokenRefreshView.as_view()),

]