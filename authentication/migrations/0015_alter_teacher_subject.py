# Generated by Django 4.0.4 on 2022-04-14 13:55

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0014_rename_classes_teacher_batches'),
    ]

    operations = [
        migrations.AlterField(
            model_name='teacher',
            name='subject',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='authentication.subject'),
        ),
    ]
