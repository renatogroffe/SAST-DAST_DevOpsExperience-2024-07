using Dapper.Contrib.Extensions;

namespace WorkerContagem.Data;

[Table("dbo.HistoricoContagem")]
public class HistoricoContagem
{
    [Key]
    public int Id { get; set; }
    public DateTime DataProcessamento { get; set; }
    public int ValorAtual { get; set; }
    public string? Producer { get; set; }
    public string? Consumer { get; set; }
    public string? QueueName { get; set; }
    public string? Mensagem { get; set; }
    public string? Kernel { get; set; }
    public string? Framework { get; set; }
}