-include .env

STACK          = sechub-e2e-test
REGION        ?=
PROFILE       ?=
INSTANCE_COUNT ?= 10

PROFILE_ARG    = $(if $(PROFILE),--profile $(PROFILE),)

deploy:
	aws cloudformation deploy \
		--stack-name $(STACK) \
		--template-file cfn-e2e.yaml \
		--region $(REGION) \
		$(PROFILE_ARG) \
		--parameter-overrides InstanceCount=$(INSTANCE_COUNT)

destroy:
	aws cloudformation delete-stack \
		--stack-name $(STACK) \
		--region $(REGION) \
		$(PROFILE_ARG)
	aws cloudformation wait stack-delete-complete \
		--stack-name $(STACK) \
		--region $(REGION) \
		$(PROFILE_ARG)

status:
	aws cloudformation describe-stacks \
		--stack-name $(STACK) \
		--region $(REGION) \
		$(PROFILE_ARG) \
		--query 'Stacks[0].{Status:StackStatus,Outputs:Outputs}'

flush:
	-aws sqs purge-queue \
		--queue-url $$(aws sqs get-queue-url --queue-name sechub-cspm-queue --region $(REGION) $(PROFILE_ARG) --query QueueUrl --output text) \
		--region $(REGION) $(PROFILE_ARG)
	-aws sqs purge-queue \
		--queue-url $$(aws sqs get-queue-url --queue-name sechub-inspector-queue --region $(REGION) $(PROFILE_ARG) --query QueueUrl --output text) \
		--region $(REGION) $(PROFILE_ARG)
	-aws sqs purge-queue \
		--queue-url $$(aws sqs get-queue-url --queue-name sechub-slack-queue --region $(REGION) $(PROFILE_ARG) --query QueueUrl --output text) \
		--region $(REGION) $(PROFILE_ARG)
