# Generated by Django 4.0.4 on 2022-04-14 13:46

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0013_rename_classmodel_batch_rename_classes_batch_batch_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='teacher',
            old_name='classes',
            new_name='batches',
        ),
    ]
