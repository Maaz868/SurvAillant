# Generated by Django 5.0.1 on 2024-04-28 08:23

import django.contrib.auth.models
import django.contrib.auth.validators
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='AnomalyPackets',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('src_ip', models.CharField(default='1.1.1.1', max_length=30)),
                ('dst_ip', models.CharField(default='1.1.1.1', max_length=30)),
                ('src_port', models.IntegerField(default=0)),
                ('dst_port', models.IntegerField(default=0)),
                ('payload_size', models.IntegerField()),
                ('protocol', models.IntegerField()),
                ('num_pkts_src', models.IntegerField()),
                ('num_pkts_dst', models.IntegerField()),
                ('modbus_function_code', models.IntegerField()),
                ('R1', models.IntegerField()),
                ('R2', models.IntegerField()),
                ('C1', models.IntegerField()),
                ('C2', models.IntegerField()),
                ('incLoad1', models.BooleanField()),
                ('decLoad1', models.IntegerField()),
                ('incLoad2', models.BooleanField()),
                ('decLoad2', models.IntegerField()),
                ('closeLoad1', models.BooleanField()),
                ('closeLoad2', models.BooleanField()),
            ],
        ),
        migrations.CreateModel(
            name='NetworkTraffic',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('normal_packets', models.IntegerField(default=0)),
                ('anomaly_packets', models.IntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='Packet',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('source_ip', models.CharField(max_length=15)),
                ('destination_ip', models.CharField(max_length=20)),
                ('protocol', models.CharField(default='', max_length=10)),
            ],
        ),
        migrations.CreateModel(
            name='PacketEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('number_of_packets', models.IntegerField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='ProtocolCount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('tcp_count', models.IntegerField(default=0)),
                ('udp_count', models.IntegerField(default=0)),
                ('modbus_count', models.IntegerField(default=0)),
                ('mqtt_count', models.IntegerField(default=0)),
                ('others_count', models.IntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='SecurityPackets',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('src_ip', models.CharField(default='1.1.1.1', max_length=30)),
                ('dst_ip', models.CharField(default='1.1.1.1', max_length=30)),
                ('src_port', models.IntegerField(default=0)),
                ('dst_port', models.IntegerField(default=0)),
                ('payload_size', models.IntegerField()),
                ('window_size', models.IntegerField()),
                ('num_pkts_src', models.IntegerField()),
                ('num_pkts_dst', models.IntegerField()),
                ('modbus_function_code', models.IntegerField()),
                ('ttl_value', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='SecurityTraffic',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('normal_packets', models.IntegerField(default=0)),
                ('security_packets', models.IntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('is_admin', models.BooleanField(default=False)),
                ('is_user_approved', models.BooleanField(default=False)),
                ('groups', models.ManyToManyField(blank=True, related_name='customuser_set', related_query_name='customuser', to='auth.group')),
                ('user_permissions', models.ManyToManyField(blank=True, related_name='customuser_set', related_query_name='customuser', to='auth.permission')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'abstract': False,
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
    ]
