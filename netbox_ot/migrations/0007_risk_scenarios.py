# Threat scenarios of a risk assessment (#46): IEC 62443-3-2 detailed assessment, one row per threat source,
# entry point, targets, consequence and risk before and after countermeasures.

import django.core.validators
import django.db.models.deletion
import netbox.models.deletion
import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dcim', '0250_cooling_infrastructure'),
        ('extras', '0144_customfield_status'),
        ('netbox_ot', '0006_risk_acceptance_sl_target'),
        ('users', '0016_default_ordering_indexes'),
    ]

    operations = [
        migrations.CreateModel(
            name='RiskScenario',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder)),
                ('description', models.CharField(blank=True, max_length=200)),
                ('comments', models.TextField(blank=True)),
                ('name', models.CharField(max_length=200)),
                ('threat_source', models.CharField(blank=True, max_length=30)),
                ('vulnerability', models.TextField(blank=True)),
                ('consequence', models.TextField(blank=True)),
                ('unmitigated_likelihood', models.PositiveSmallIntegerField(blank=True, null=True, validators=[django.core.validators.MinValueValidator(1)])),
                ('unmitigated_impact', models.PositiveSmallIntegerField(blank=True, null=True, validators=[django.core.validators.MinValueValidator(1)])),
                ('unmitigated_risk', models.CharField(blank=True, max_length=20)),
                ('countermeasures', models.TextField(blank=True)),
                ('residual_likelihood', models.PositiveSmallIntegerField(blank=True, null=True, validators=[django.core.validators.MinValueValidator(1)])),
                ('residual_impact', models.PositiveSmallIntegerField(blank=True, null=True, validators=[django.core.validators.MinValueValidator(1)])),
                ('residual_risk', models.CharField(blank=True, max_length=20)),
                ('assessment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scenarios', to='netbox_ot.riskassessment')),
                ('entry_conduit', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='risk_scenarios', to='netbox_ot.conduit')),
                ('entry_flow', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='risk_scenarios', to='netbox_ot.flow')),
                ('owner', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='users.owner')),
                ('requirement_statuses', models.ManyToManyField(blank=True, related_name='risk_scenarios', to='netbox_ot.requirementstatus')),
                ('tags', taggit.managers.TaggableManager(through='extras.TaggedItem', to='extras.Tag')),
                ('targets', models.ManyToManyField(blank=True, related_name='ot_risk_scenarios', to='dcim.device')),
            ],
            options={
                'verbose_name': 'risk scenario',
                'verbose_name_plural': 'risk scenarios',
                'ordering': ('assessment', 'name', 'pk'),
            },
            bases=(netbox.models.deletion.DeleteMixin, models.Model),
        ),
    ]
