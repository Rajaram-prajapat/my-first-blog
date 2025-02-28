from django.db.models import F
from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, Http404
from .models import Choice, Question
from django.urls import reverse
from django.views import generic
from django.utils import timezone


# Index view using CBV
class IndexView(generic.ListView):
    template_name = "polls/index.html"
    context_object_name = "latest_question_list"

    def get_queryset(self):
        """
        Return the last five published questions (not including those set to be
        published in the future).
        """
        return Question.objects.filter(pub_date__lte=timezone.now()).order_by("-pub_date")[:5]


# Detail view using CBV
class DetailView(generic.DetailView):
    model = Question
    template_name = "polls/detail.html"

    def get_queryset(self):
        """
        Excludes any questions that aren't published yet.
        """
        return Question.objects.filter(pub_date__lte=timezone.now())


# Results view using CBV
class ResultsView(generic.DetailView):
    model = Question
    template_name = 'polls/results.html'
    context_object_name = 'question'

    def get_queryset(self):
        try:
            return Question.objects.filter(id=self.kwargs['pk'], pub_date__lte=timezone.now())
        except Question.DoesNotExist:
            raise Http404("No Question found matching the query.")


# Vote view using FBV
def vote(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    try:
        selected_choice = question.choice_set.get(pk=request.POST["choice"])
    except (KeyError, Choice.DoesNotExist):
        # Redisplay the question voting form with an error message
        return render(
            request,
            "polls/detail.html",
            {
                "question": question,
                "error_message": "You didn't select a choice.",
            },
        )
    else:
        selected_choice.votes = F("votes") + 1  # Increment the vote count
        selected_choice.save()
        # Redirect to the results page after voting
        return HttpResponseRedirect(reverse("polls:results", args=(question.id,)))