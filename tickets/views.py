# tickets/views.py
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from bson import ObjectId
from django.utils import timezone
from .models import Ticket
from .serializers import TicketListSerializer, TicketSerializer

class TicketCreateView(generics.CreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TicketSerializer
    queryset = Ticket.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ticket = serializer.save()

        return Response({
            "message": "Ticket created successfully.",
            "ticket": TicketSerializer(ticket).data
        }, status=status.HTTP_201_CREATED)


class TicketListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TicketListSerializer
    queryset = Ticket.objects.all().order_by("-created_at")

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        response_data = {
            "message": "Tickets fetched successfully.",
            "count": queryset.count(),
            "tickets": serializer.data
        }

        return Response(response_data, status=status.HTTP_200_OK)



class TicketOpenListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TicketListSerializer

    def get_queryset(self):
        return Ticket.objects.filter(status=Ticket.Status.OPEN).order_by("-created_at")

    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        serializer = self.get_serializer(qs, many=True)

        data = {
            "message": "Open tickets fetched successfully.",
            "count": qs.count(),
            "timestamp": timezone.now().isoformat(),
            "tickets": serializer.data,
        }
        return Response(data, status=status.HTTP_200_OK)


class TicketClosedListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TicketListSerializer

    def get_queryset(self):
        return Ticket.objects.filter(status=Ticket.Status.CLOSE).order_by("-created_at")

    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        serializer = self.get_serializer(qs, many=True)

        data = {
            "message": "Closed tickets fetched successfully.",
            "count": qs.count(),
            "timestamp": timezone.now().isoformat(),
            "tickets": serializer.data,
        }
        return Response(data, status=status.HTTP_200_OK)
    

class TicketDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    queryset = Ticket.objects.all()
    serializer_class = TicketListSerializer  # default for GET
    lookup_field = "_id"

    def get_object(self):
        """
        Accept 'detail_id' or '_id' in URL and convert to ObjectId.
        """
        detail_id = self.kwargs.get("detail_id") or self.kwargs.get("_id")
        if not detail_id:
            return get_object_or_404(Ticket, _id=None)  # will raise 404
        try:
            obj_id = ObjectId(detail_id)
        except Exception:
            # fallback: try as-is (some setups store _id as string)
            return get_object_or_404(Ticket, _id=detail_id)
        return get_object_or_404(Ticket, _id=obj_id)

    def get_serializer_class(self):
        # Use TicketSerializer for write operations
        if self.request.method in ("PUT", "PATCH"):
            return TicketSerializer
        return TicketListSerializer

    def _serialize_with_iso_ts(self, ticket):
        """
        Helper: returns serializer.data dict but ensures created_at/updated_at are ISO strings.
        """
        data = TicketListSerializer(ticket).data
        if hasattr(ticket, "created_at") and ticket.created_at is not None:
            data["created_at"] = ticket.created_at.isoformat()
        if hasattr(ticket, "updated_at") and ticket.updated_at is not None:
            data["updated_at"] = ticket.updated_at.isoformat()
        return data

    def retrieve(self, request, *args, **kwargs):
        ticket = self.get_object()
        data = self._serialize_with_iso_ts(ticket)
        return Response(
            {
                "message": "Ticket fetched successfully.",
                "ticket": data,
                "timestamp": timezone.now().isoformat()
            },
            status=status.HTTP_200_OK
        )

    def update(self, request, *args, **kwargs):
        """
        Update the ticket. Return changed fields, previous values for changed fields,
        and updated ticket (with ISO timestamps).
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()

        # capture previous snapshot for tracked fields
        prev = {
            "subject": instance.subject,
            "asset": instance.asset,
            "description": instance.description,
            "category": instance.category,
            "status": instance.status,
        }

        # perform update via serializer
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        updated_ticket = serializer.save()

        # compute changed fields and previous->new mapping
        changed_fields = []
        prev_new_changes = {}
        for field, old_val in prev.items():
            new_val = getattr(updated_ticket, field)
            # compare (handle None)
            if (old_val is None and new_val is not None) or (old_val != new_val):
                changed_fields.append(field)
                prev_new_changes[field] = {"old": old_val, "new": new_val}

        # Build message
        if changed_fields:
            if "status" in changed_fields:
                msg = f"Ticket updated. Status changed from '{prev['status']}' to '{updated_ticket.status}'."
            else:
                msg = f"Ticket updated successfully. Fields changed: {changed_fields}."
        else:
            msg = "No changes detected; ticket remains unchanged."

        ticket_data = self._serialize_with_iso_ts(updated_ticket)

        response = {
            "message": msg,
            "changed_fields": changed_fields,
            "changes": prev_new_changes,
            "ticket": ticket_data,
            "timestamp": timezone.now().isoformat(),
        }
        return Response(response, status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        # alias PATCH to update with partial=True
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """
        Delete ticket and return a friendly summary including created_at/updated_at ISO timestamps.
        """
        ticket = self.get_object()
        ticket_id = str(ticket._id)
        ticket_subject = ticket.subject
        # capture timestamps before deletion
        created_at = ticket.created_at.isoformat() if hasattr(ticket, "created_at") and ticket.created_at else None
        updated_at = ticket.updated_at.isoformat() if hasattr(ticket, "updated_at") and ticket.updated_at else None

        # Optionally prepare full deleted ticket data (safe to return)
        deleted_summary = {
            "id": ticket_id,
            "subject": ticket_subject,
            "created_at": created_at,
            "updated_at": updated_at,
        }

        ticket.delete()

        response = {
            "message": f"Ticket '{ticket_subject}' (id: {ticket_id}) deleted successfully.",
            "ticket": deleted_summary,
            "timestamp": timezone.now().isoformat()
        }
        return Response(response, status=status.HTTP_200_OK)