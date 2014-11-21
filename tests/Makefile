.PHONY: bootstrap clean distclean manage test test_unit

ENV ?= env
VENV = $(shell python -c "import sys; print(int(hasattr(sys, 'real_prefix')));")

ifeq ($VENV,1)
	PYTHON = python
else
	PYTHON = $(ENV)/bin/python
endif

bootstrap:
	bootstrapper -e $(ENV)/

clean:
	find . -name "*.pyc" -delete

distclean: clean
	rm -rf $(ENV)/

manage:
	$(PYTHON) manage.py $(COMMAND)

test: bootstrap test_unit

test_unit:
	COMMAND="test $(TEST_ARGS)" $(MAKE) manage
