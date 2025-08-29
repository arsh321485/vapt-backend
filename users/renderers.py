from rest_framework import renderers
import json
from rest_framework.renderers import JSONRenderer

class UserRenderer(JSONRenderer):
    charset = 'utf-8'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = ''
        if isinstance(data, dict) and 'ErrorDetail' in str(data):
            response = {'errors': data}
        else:
            response = data
        return super().render(response, accepted_media_type, renderer_context)