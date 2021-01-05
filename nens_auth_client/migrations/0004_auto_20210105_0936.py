# Generated by Django 2.2.16 on 2021-01-05 09:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('nens_auth_client', '0003_invite_add_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='remoteuser',
            name='access_token',
            field=models.TextField(blank=True, help_text='The most access token provided by the external identity provider.'),
        ),
        migrations.AddField(
            model_name='remoteuser',
            name='id_token',
            field=models.TextField(blank=True, help_text='The most recent ID token provided by the external identity provider.'),
        ),
        migrations.AddField(
            model_name='remoteuser',
            name='refresh_token',
            field=models.TextField(blank=True, help_text='The most refresh token provided by the external identity provider.'),
        ),
    ]
