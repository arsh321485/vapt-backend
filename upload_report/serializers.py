from rest_framework import serializers
from .models import UploadReport
from users.models import User

class UploadReportSerializer(serializers.ModelSerializer):
    _id = serializers.SerializerMethodField()
    admin = serializers.SerializerMethodField()
    file = serializers.SerializerMethodField()

    admin_email = serializers.CharField(source='admin.email', read_only=True)

    class Meta:
        model = UploadReport
        fields = [
            '_id',
            'file',
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

    def get_admin(self, obj):
        return str(obj.admin.id) if obj.admin else None

    def get_file(self, obj):
        request = self.context.get("request")
        if obj.file and request:
            return request.build_absolute_uri(obj.file.url)
        return None