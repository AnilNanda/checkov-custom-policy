from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class IAMTag(BaseResourceCheck):
    def __init__(self):
        name = "Ensure IAM users are tagged"
        id = "CKV_AWS_163452"
        supported_resources = ['aws_iam_user']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        """
        Looks for encryption configuration at aws_db_instance:
        https://www.terraform.io/docs/providers/aws/d/db_instance.html
        :param conf: aws_db_instance configuration
        :return: <CheckResult>
        """
        if 'tags' in conf.keys():
            key = conf['tags'][0]['Inactivate']
            if key:
                return CheckResult.PASSED
        return CheckResult.FAILED

check = IAMTag()
