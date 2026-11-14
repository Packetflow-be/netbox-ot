# What a risk assessment arrives at (#46): the SL-T of its zone or conduit (IEC 62443-3-2 ZCR 5), and an explicit,
# time-bound acceptance of a residual risk above the tolerable risk by the asset owner. All optional, so existing
# assessments stay as they are.

import django.contrib.postgres.fields
import django.db.models.deletion
from django.db import migrations, models

import netbox_ot.sl


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_ot", "0005_risk_matrix"),
        ("tenancy", "0026_consolidate_unique_constraints"),
    ]

    operations = [
        migrations.AddField(
            model_name="riskassessment",
            name="sl_target",
            field=django.contrib.postgres.fields.ArrayField(
                base_field=models.PositiveSmallIntegerField(), blank=True, null=True, size=7,
                validators=[netbox_ot.sl.validate],
            ),
        ),
        migrations.AddField(
            model_name="riskassessment",
            name="risk_accepted_by",
            field=models.ForeignKey(
                blank=True, null=True, on_delete=django.db.models.deletion.PROTECT,
                related_name="ot_risk_acceptances", to="tenancy.contact",
            ),
        ),
        migrations.AddField(
            model_name="riskassessment",
            name="risk_accepted_on",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="riskassessment",
            name="risk_accepted_until",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="riskassessment",
            name="risk_acceptance",
            field=models.TextField(blank=True),
        ),
    ]
