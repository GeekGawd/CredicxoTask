# Generated by Django 4.0.4 on 2022-04-12 14:10

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0003_user_status'),
    ]

    operations = [
        migrations.CreateModel(
            name='ClassModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ],
        ),
        migrations.CreateModel(
            name='Student',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('roll_number', models.IntegerField(unique=True)),
                ('classes', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='authentication.classmodel')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='teacher',
            name='classes',
            field=models.ManyToManyField(to='authentication.classmodel'),
        ),
    ]
