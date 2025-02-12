from odoo import api, models
import logging

_logger = logging.getLogger(__name__)


class AccountMoveSend(models.AbstractModel):
    _inherit = "account.move.send"

    @api.model
    def _prepare_invoice_pdf_report(self, invoice_data):
        """Prepare the pdf report for the invoice passed as parameter.
        :param invoice_data:    The collected data for the invoice so far.
        """
        _logger.debug("Invoice Data Keys: %s", invoice_data.keys())
        invoice = invoice_data.get('move')
        if not invoice:
            _logger.error("No invoice found in invoice_data.")
            return super()._prepare_invoice_pdf_report(invoice_data)
        if invoice.is_purchase_withhold():
            if invoice.invoice_pdf_report_id:
                return
            ActionReport = self.env["ir.actions.report"]
            report_idxml = "l10n_ec_withhold.action_report_withholding_ec"
            content, _report_format = ActionReport._render(
                report_idxml, invoice.ids)
            invoice_data["pdf_attachment_values"] = {
                "raw": content,
                "name": invoice._get_invoice_report_filename(),
                "mimetype": "application/pdf",
                "res_model": invoice._name,
                "res_id": invoice.id,
                "res_field": "invoice_pdf_report_file",  # Binary field
            }
            return
        return super()._prepare_invoice_pdf_report(invoice_data)
