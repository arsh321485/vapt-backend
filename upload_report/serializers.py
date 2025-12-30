from rest_framework import serializers
from .models import UploadReport
from users.models import User
from location.models import Location

# class UploadReportSerializer(serializers.ModelSerializer):
#     location = serializers.PrimaryKeyRelatedField(queryset=Location.objects.all(), required=False, allow_null=True)
#     admin = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), required=False, allow_null=True)
#     location_name = serializers.CharField(source='location.location_name', read_only=True)
#     admin_email = serializers.CharField(source='admin.email', read_only=True)

#     class Meta:
#         model = UploadReport
#         fields = [
#             '_id', 'file', 'location', 'location_name',
#             'admin', 'admin_email', 'member_type',
#             'uploaded_at', 'status', 'parsed_count','created_at','updated_at'
#         ]
#         read_only_fields = ['_id', 'uploaded_at', 'created_at','updated_at','status', 'parsed_count']


class UploadReportSerializer(serializers.ModelSerializer):
    _id = serializers.SerializerMethodField()
    location = serializers.SerializerMethodField()
    admin = serializers.SerializerMethodField()

    location_name = serializers.CharField(source='location.location_name', read_only=True)
    admin_email = serializers.CharField(source='admin.email', read_only=True)

    class Meta:
        model = UploadReport
        fields = [
            '_id',
            'file',
            'location',
            'location_name',
            'admin',
            'admin_email',
            'member_type',
            'uploaded_at',
            'status',
            'parsed_count',
            'created_at',
            'updated_at'
        ]

    def get__id(self, obj):
        return str(obj._id) if obj._id else None

    def get_location(self, obj):
        return str(obj.location._id) if obj.location else None

    def get_admin(self, obj):
        return str(obj.admin.id) if obj.admin else None