import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Send, Eraser } from "lucide-react";

import { useSession } from "@/context/SessionContext";
import { ButtonGroup } from "@/components/ui/button-group";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";

interface URLSendViewProps {
  scheme: string;
}

export function URLSendView({ scheme }: URLSendViewProps) {
  const { t } = useTranslation();
  const [url, setURL] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const { fruity } = useSession();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setURL(scheme + "://");
    textareaRef.current?.focus();
  }, [scheme]);

  const handleSend = async () => {
    if (isLoading || !fruity) {
      return;
    }

    setError(null);
    setIsLoading(true);

    try {
      await fruity.url.open(url);
    } catch (e) {
      setError(`${e}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter") {
      event.preventDefault();
      handleSend();
    }
  };

  const reset = () => {
    if (isLoading) {
      return;
    }
    setURL(scheme + "://");
    textareaRef.current?.focus();
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex flex-col flex-1 p-2 gap-2">
        <Textarea
          ref={textareaRef}
          value={url}
          onChange={(e) => setURL(e.target.value)}
          onKeyDown={handleKeyDown}
          className="font-mono resize-none flex-1 min-h-0"
          placeholder={t("enter_url_scheme")}
          readOnly={isLoading}
        />
        <div className="flex justify-end shrink-0">
          <div className="inline-flex items-center gap-2">
            {error && <span className="text-sm text-destructive">{error}</span>}
            <ButtonGroup>
              <Button
                size="sm"
                onClick={reset}
                variant="outline"
                disabled={isLoading}
                title={t("reset")}
                className="px-2"
              >
                <Eraser className="size-4" />
              </Button>
              <Button
                size="sm"
                onClick={handleSend}
                className="gap-2"
                variant="outline"
                disabled={isLoading}
              >
                <Send className="size-4" />
                {t("send")}
              </Button>
            </ButtonGroup>
          </div>
        </div>
      </div>
    </div>
  );
}
