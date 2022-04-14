from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from authentication.models import Teacher, Qualification, Batch, Student, User, Subject
from django.db.models import Q
from authentication.forms import UserCreationForm

# Register your models here.

class UserAdmin(BaseUserAdmin):
    """Customizing the Default Admin for Django"""
    ordering = ['id']
    list_display = ['email','id', 'name']
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (('Personal Info'), {'fields': ('name',)}),
        (
            ('Permissions'),
            {'fields': ('is_active', 'is_staff', 'is_superuser')}
        ),
        (('Important dates'), {'fields': ('last_login',)}),
        ('Group Permissions', {
            'classes': ('collapse',),
            'fields': ('groups', 'user_permissions', )
        })
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email','name','password1', 'password2', 'dob', 'address', 'phone_number', 'status'),
        }),
    )
    add_form = UserCreationForm


class TeacherUserAdmin(BaseUserAdmin):

    """Making a Admin Panel just for the Teacher. With the ability to list and add Students."""


    ordering = ['id']
    list_display = ['email','id', 'name']
    fieldsets = (
        (None, {'fields': ('email', 'password', 'groups')}),
        (('Personal Info'), {'fields': ('name',)}),
        (('Important dates'), {'fields': ('last_login',)})
    )
    readonly_fields = ('groups',)
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email','name','password1', 'password2', 'dob', 'address', 'phone_number')
        }),
    )
    add_form = UserCreationForm


    def get_queryset(self, request):
        qs = super(TeacherUserAdmin, self).get_queryset(request)
        if not request.user.is_superuser:
            return qs.filter(Q(is_superuser=False) & Q(is_staff=False))
        return qs

class TeacherAdminArea(admin.AdminSite):
    """Making a Admin Panel just for the Teacher. With the ability to list and add Students."""
    site_header = "Teacher's Login"

    def index(self, request, extra_context=None):
        if extra_context is None:
            extra_context = {}
        extra_context["app_list"] = admin.AdminSite.get_app_list(self, request)
        return super(TeacherAdminArea, self).index(request, extra_context)

teacher_login = TeacherAdminArea(name="TeacherAdmin")

"""Registering Model for the Teacher Admin Panel"""
teacher_login.register(Student)
teacher_login.register(User, TeacherUserAdmin)
teacher_login.register(Batch)


"""Registering Model for the Django SuperUser Admin Panel"""
admin.site.register(User, UserAdmin)
admin.site.register(Teacher)
admin.site.register(Qualification)
admin.site.register(Batch)
admin.site.register(Student)
admin.site.register(Subject)




